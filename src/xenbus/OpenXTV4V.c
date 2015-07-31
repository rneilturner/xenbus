/* ## AIS Copyright ##
 */

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <stdlib.h>
#include <xen.h>

#include <OpenXTV4V/OpenXTV4V.h>
#include <OpenXTV4V/OpenXTV4VKernel.h>

#include "dbg_print.h"

static NTSTATUS V4vCtrlInitializeFile(XENV4V_CONTEXT *aCTX, V4V_INIT_VALUES *aInitValues, PIRP aIRP) {
    NTSTATUS status = STATUS_SUCCESS;

    if (aCTX == NULL) {
        Error("no file context!\n");
        return STATUS_INVALID_HANDLE;
    }

    if (aInitValues->rxEvent == NULL) {
        Error("no event handle!\n");
        return STATUS_INVALID_HANDLE;
    }

    // Reference the event objects
    status = ObReferenceObjectByHandle(aInitValues->rxEvent,
                                       EVENT_MODIFY_STATE,
                                       *ExEventObjectType,
                                       aIRP->RequestorMode,
                                       (void **)&aCTX->kevReceive,
                                       NULL);

    if (!NT_SUCCESS(status)) {
        Error("failed to get a reference to the receive event - error: 0x%x\n", status);
        return status;
    }

    aCTX->ringLength = aInitValues->ringLength;

    // Straighten out the ring
    if (aCTX->ringLength > PAGE_SIZE) {
        aCTX->ringLength = (aCTX->ringLength + XENV4V_RING_MULT - 1) & ~(XENV4V_RING_MULT - 1);
    }
    else {
        aCTX->ringLength = PAGE_SIZE; // minimum to guarantee page alignment
    }

    InterlockedExchange(&aCTX->state, XENV4V_STATE_IDLE);

    return STATUS_SUCCESS;
}

static unsigned V4vGetAcceptPrivate(ULONG aCode, VOID *aBuffer, V4V_ACCEPT_PRIVATE **aAcceptPrivate, struct v4v_addr **aPeer)
{
    ULONG size = 0;

    UNREFERENCED_PARAMETER(aCode);

#if defined(_WIN64)
    if (aCode == V4V_IOCTL_ACCEPT_32)
    {
        V4V_ACCEPT_VALUES_32 *avs32 = (V4V_ACCEPT_VALUES_32*)aBuffer;

        *aPeer = &avs32->peerAddr;
        *aAcceptPrivate = (V4V_ACCEPT_PRIVATE*)((UCHAR*)avs32 + FIELD_OFFSET(V4V_ACCEPT_VALUES_32, priv));
        size = sizeof(V4V_ACCEPT_VALUES_32);
    }
    else
#endif
    {
        V4V_ACCEPT_VALUES *avs = (V4V_ACCEPT_VALUES*)aBuffer;

        *aPeer = &avs->peerAddr;
        *aAcceptPrivate = (V4V_ACCEPT_PRIVATE*)((UCHAR*)avs + FIELD_OFFSET(V4V_ACCEPT_VALUES, priv));
        size = sizeof(V4V_ACCEPT_VALUES);
    }

    return size;
}

static __inline NTSTATUS
V4vSimpleCompleteIrp(PIRP aIRP, NTSTATUS aStatus)
{
    aIRP->IoStatus.Information = 0;
    aIRP->IoStatus.Status = aStatus;
    IoCompleteRequest(aIRP, IO_NO_INCREMENT);
    return aStatus;
}

static NTSTATUS
V4vInternalMsgCompletion(PDEVICE_OBJECT fdo, PIRP irp, PVOID ctx)
{
    XENV4V_CTRL_MSG  *cmsg = (XENV4V_CTRL_MSG*)ctx;
    XENV4V_EXTENSION *pde;
    FILE_OBJECT      *pfo;
    PMDL              mdl = NULL, nextMdl = NULL;

    UNREFERENCED_PARAMETER(fdo);

    // Determine message type and hold a pointers for use at the end
    if (cmsg->sh.flags == V4V_SHF_RST) {
        pde = ((XENV4V_RESET*)ctx)->pde;
        pfo = ((XENV4V_RESET*)ctx)->pfo;
    }
    else {
        pde = ((XENV4V_ACKNOWLEDGE*)ctx)->pde;
        pfo = ((XENV4V_ACKNOWLEDGE*)ctx)->pfo;
    }

    if (irp->IoStatus.Status == STATUS_CANCELLED) {
        Trace("IRP(%d) was cancelled.", cmsg->sh.flags);
    }
    else if (!NT_SUCCESS(irp->IoStatus.Status)) {
        Error("IRP(%d) failed - status: 0x%x.", cmsg->sh.flags, irp->IoStatus.Status);
    }

    if ((irp->AssociatedIrp.SystemBuffer != NULL)&&(irp->Flags & IRP_DEALLOCATE_BUFFER)) {
        // For completeness in case we use buffered IO
        ExFreePoolWithTag(ctx, XENV4V_TAG);
    }
    else if (irp->MdlAddress != NULL) {
        // We use DIRECT_IO so we have to unlock things before we can free the buffer, this
        // is where we will come through. This is never a zero write so there is always an MDL.
        for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
            nextMdl = mdl->Next;
            MmUnlockPages(mdl);
            IoFreeMdl(mdl); // This function will also unmap pages.
        }
        irp->MdlAddress = NULL;
        ExFreePoolWithTag(ctx, XENV4V_TAG);
    }

    IoReleaseRemoveLock(&pde->removeLock, irp);
    IoFreeIrp(irp);
    ObDereferenceObject(pfo);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static IO_WORKITEM_ROUTINE V4vSendWorkItem;
static VOID NTAPI
V4vSendWorkItem(PDEVICE_OBJECT fdo, PVOID ctx)
{
    XENV4V_CTRL_MSG       *cmsg = (XENV4V_CTRL_MSG*)ctx;
    XENV4V_EXTENSION      *pde;
    FILE_OBJECT           *pfo;
    IRP                   *irp = NULL;
    XENV4V_RESET          *rst;
    XENV4V_ACKNOWLEDGE    *ack;
    NTSTATUS               status;

    UNREFERENCED_PARAMETER(fdo);

    if (cmsg->sh.flags == V4V_SHF_RST) {
        rst = (XENV4V_RESET*)cmsg;
        pde = rst->pde;
        pfo = rst->pfo;
        IoFreeWorkItem(rst->pwi);
        rst->pwi = NULL;

        irp = IoBuildAsynchronousFsdRequest(IRP_MJ_WRITE, pde->fdo, rst, sizeof(XENV4V_RESET), NULL, NULL);
        if (irp == NULL) {
            Error("Send RST failed - out of memory allocating IRP\n");
            goto wi_err;
        }
        irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_RST);
        irp->Tail.Overlay.DriverContext[1] = (PVOID)(ULONG_PTR)(XENV4V_RST_MAGIC);

        IoSetCompletionRoutine(irp, V4vInternalMsgCompletion, rst, TRUE, TRUE, TRUE);
    }
    else {
        ack = (XENV4V_ACKNOWLEDGE*)cmsg;
        pde = ack->pde;
        pfo = ack->pfo;
        IoFreeWorkItem(ack->pwi);
        ack->pwi = NULL;

        irp = IoBuildAsynchronousFsdRequest(IRP_MJ_WRITE, pde->fdo, ack, sizeof(XENV4V_ACKNOWLEDGE), NULL, NULL);
        if (irp == NULL) {
            Error("Send ACK failed - out of memory allocating IRP\n");
            goto wi_err;
        }
        irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_ACK);
        irp->Tail.Overlay.DriverContext[1] = (PVOID)(ULONG_PTR)(XENV4V_ACK_MAGIC);

        IoSetCompletionRoutine(irp, V4vInternalMsgCompletion, ack, TRUE, TRUE, TRUE);
    }

    // Associate the file object with the target IOSL - ref count already bumped during work item queueing
    IoGetNextIrpStackLocation(irp)->FileObject = pfo;

    status = IoAcquireRemoveLock(&pde->removeLock, irp);
    if (!NT_SUCCESS(status)) {
        Error("IoAcquireRemoveLock(%d) for send failed - status: 0x%x.", cmsg->sh.flags, status);
        goto wi_err;
    }

    status = IoCallDriver(pde->fdo, irp);
    if (!NT_SUCCESS(status)) {
        Error("IoCallDriver(%d) for send failed - status: 0x%x.", cmsg->sh.flags, status);
        // Undo the lock here
        IoReleaseRemoveLock(&pde->removeLock, irp);
        goto wi_err;
    }

    return;

wi_err:
    if (irp != NULL) {
        IoFreeIrp(irp);
    }

    // Restore ref count on parent PFO
    ObDereferenceObject(pfo);

    // Normally freed in completion routine unless the driver call fails.
    ExFreePoolWithTag(cmsg, XENV4V_TAG);
}

void V4vDoAccepts(XENV4V_EXTENSION *aPDE, XENV4V_CONTEXT *aCTX) {
    NTSTATUS            status;
    KLOCK_QUEUE_HANDLE  lqh;
    PIO_STACK_LOCATION  isl;
    PIRP                nextIrp = NULL;
    XENV4V_QPEEK        peek;
    ULONG               ioControlCode;
    PVOID               ioBuffer;
    struct v4v_addr    *peer;
    ULONG               size;
    XENV4V_CONTEXT     *actx;
    XENV4V_SYN         *sptr;
    V4V_ACCEPT_PRIVATE *priv;

    peek.types = XENV4V_PEEK_STREAM; // process for stream types
    peek.ops   = XENV4V_PEEK_ACCEPT; // accept ops
    peek.pfo   = aCTX->pfoParent;     // for a specific file object

    // Lock the SYN list state and process SYN entries. For each,
    // try to locate an accept IRP in the queue for this listener.
    KeAcquireInStackQueuedSpinLock(&aCTX->u.listener.synLock, &lqh);

    do {
        if (aCTX->u.listener.synCount == 0) {
            // No data so clear any events indicating pending accepts.
            KeClearEvent(aCTX->kevReceive);
            break; // no more to read
        }

        // SYNs, any pending accepts?
        nextIrp = IoCsqRemoveNextIrp(&aPDE->csqObject, &peek);
        if (nextIrp == NULL) {
            // Nobody to accept it so tell the listener there are SYNs waiting.
            // Set the data ready event for clients who use it.
            KeSetEvent(aCTX->kevReceive, EVENT_INCREMENT, FALSE);
            break;
        }

        // Now there is a SYN and an accept IRP to take it.
        isl           = IoGetCurrentIrpStackLocation(nextIrp);
        ioControlCode = isl->Parameters.DeviceIoControl.IoControlCode;
        ioBuffer      = nextIrp->AssociatedIrp.SystemBuffer;

        // Gather the private accept information
        size = V4vGetAcceptPrivate(ioControlCode, ioBuffer, &priv, &peer);

        // Get the stashed referenced context pointer for the new accepter
#if defined(_WIN64)
        actx = (XENV4V_CONTEXT*)priv->q.a;
#else
        actx = (XENV4V_CONTEXT*)priv->d.a;
#endif

        // Pop the next in order from the head of the list
        ASSERT(aCTX->u.listener.synHead != NULL);
        ASSERT(aCTX->u.listener.synTail != NULL);
        sptr = aCTX->u.listener.synHead;
        if (aCTX->u.listener.synHead != aCTX->u.listener.synTail) {
            // More than one on the list
            aCTX->u.listener.synHead = sptr->next;
        }
        else {
            // Only one on the list, reset pointers
            aCTX->u.listener.synHead = NULL;
            aCTX->u.listener.synTail = NULL;
        }

        aCTX->u.listener.synCount--;
        ASSERT(aCTX->u.listener.synCount >= 0);

        // Finish the accept, clear the SYN entry and drop the ref count on the context
        actx->sdst   = sptr->sdst;
        actx->connId = sptr->connId;
        (*peer)      = sptr->sdst;
        RtlZeroMemory(sptr, sizeof(XENV4V_SYN));
        V4vReleaseContext(aPDE, actx, TRUE);
        InterlockedExchange(&actx->state, XENV4V_STATE_ACCEPTED);

        // Send the ACK to our peer
        status = V4vSendAcknowledge(aPDE, actx);
        if (!NT_SUCCESS(status)) {
            // Fail the IRP and go to the disconnected state for the new context
            V4vSimpleCompleteIrp(nextIrp, status);
            InterlockedExchange(&actx->state, XENV4V_STATE_DISCONNECTED);
            continue;
        }

        // Complete the IRP - this will finish the accept call. Set the IOCTL output
        // buffer to the size appropriate for the user mode caller (32b vs 64b).
        nextIrp->IoStatus.Information = size;
        nextIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(nextIrp, IO_NO_INCREMENT);
    } while (TRUE);

    KeReleaseInStackQueuedSpinLock(&lqh);
}

VOID
V4vSendReset(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, uint32_t connId, v4v_addr_t *dst, BOOLEAN noq)
{
    NTSTATUS      status;
    ULONG32       written = 0;
    V4V_STREAM    sh;
    XENV4V_RESET *rst = NULL;

    // Try to send it right here first
    sh.conid = connId;
    sh.flags = V4V_SHF_RST;
    status = V4vSend(&ctx->ringObject->ring->id.addr,
                     dst,
                     V4V_PROTO_STREAM,
                     &sh,
                     sizeof(V4V_STREAM),
                     &written);

    if (status == STATUS_RETRY) {
        if (noq) {
            return;
        }

        // Ring is full, send an IRP to ourselves to queue the RST
        rst = (XENV4V_RESET*)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENV4V_RESET), XENV4V_TAG);
        if (rst == NULL) {
            Error("send RST failed - out of memory\n");
            goto reset_err;
        }

        // Allocated a work item to do this in another context to avoid re-entering our locks etc.
        rst->pwi = IoAllocateWorkItem(pde->fdo);
        if (rst->pwi == NULL) {
            Error("Failed to allocate send RST work item - out of memory.\n");
            goto reset_err;
        }

        // Setup RST, add a ref to the parent for the call back to ourselves.
        rst->dst = (*dst);
        rst->sh  = sh;
        rst->pde = pde;
        rst->pfo = ctx->pfoParent;
        ObReferenceObject(ctx->pfoParent);

        IoQueueWorkItem(rst->pwi, V4vSendWorkItem, DelayedWorkQueue, rst);
    }
    else if ((!NT_SUCCESS(status))&&(status != STATUS_VIRTUAL_CIRCUIT_CLOSED)) {
        Error("Send RST failed - error: 0x%x\n", status);
    }

    return;

reset_err:
    if (rst != NULL) {
        ExFreePoolWithTag(rst, XENV4V_TAG);
    }
}

NTSTATUS
V4vSendAcknowledge(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    NTSTATUS            status = STATUS_NO_MEMORY;
    XENV4V_ACKNOWLEDGE *ack = NULL;

    // For ACKs (from accepted contexts), always create and push a write IRP to the back of the queue.
    ack = (XENV4V_ACKNOWLEDGE*)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENV4V_ACKNOWLEDGE), XENV4V_TAG);
    if (ack == NULL) {
        Error("send ACK failed - out of memory\n");
        goto acknowledge_err;
    }

    // Allocated a work item to do this in another context to avoid re-entering our locks etc.
    ack->pwi = IoAllocateWorkItem(pde->fdo);
    if (ack->pwi == NULL) {
        Error("Failed to allocate send ACK work item - out of memory.\n");
        goto acknowledge_err;
    }

    // Setup ACK, add a ref to the parent for the call back to ourselves.
    ack->sh.conid = (uint32_t)ctx->connId;
    ack->sh.flags = V4V_SHF_ACK;
    ack->pde      = pde;
    ack->pfo      = ctx->pfoParent;
    ObReferenceObject(ctx->pfoParent);

    IoQueueWorkItem(ack->pwi, V4vSendWorkItem, DelayedWorkQueue, ack);

    return STATUS_SUCCESS;

acknowledge_err:
    if (ack != NULL) {
        ExFreePoolWithTag(ack, XENV4V_TAG);
    }

    return status;
}

ULONG32
V4vReleaseContext(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, BOOLEAN lock)
{
    KLOCK_QUEUE_HANDLE  lqh = {0};
    ULONG32             count;
    FILE_OBJECT        *pfo;
    LONG                val;

    val = InterlockedExchangeAdd(&ctx->type, 0);

    if (lock) {
        KeAcquireInStackQueuedSpinLock(&pde->contextLock, &lqh);
    }
    ASSERT(ctx->refc != 0); // SNO, really bad
    count = --ctx->refc;

    // For listeners only, unlink the context here when there are no more contexts associated with it
    if ((val == XENV4V_TYPE_LISTENER)&&(count == 1)) {
        RemoveEntryList(&ctx->le);
        count = --ctx->refc;
        pde->contextCount--;
        ASSERT(pde->contextCount >= 0); // SNO, really bad
    }

    if (lock) {
        KeReleaseInStackQueuedSpinLock(&lqh);
    }

    // When the count goes to zero, clean it all up. We are out of the list so a lock is not needed.
    // N.B. if we end up doing any cleanup that cannot happen at DISPATCH, we will need a work item.
    if (count == 0) {
        // Type specific cleanup
        if (val == XENV4V_TYPE_ACCEPTER) {
            V4vFlushAccepterQueueData(ctx);
            ASSERT(ctx->u.accepter.listenerContext != NULL);
            V4vReleaseContext(pde, ctx->u.accepter.listenerContext, lock);
        }
        else if (val == XENV4V_TYPE_LISTENER) {
            ASSERT(ctx->u.listener.synList != NULL);
            ExFreePoolWithTag(ctx->u.listener.synList, XENV4V_TAG);
        }

        pfo = ctx->pfoParent;
        // Cleanup the ring - if it is shared, this will just drop the ref count.
        if (ctx->ringObject != NULL) {
            V4vReleaseRing(pde, ctx->ringObject);
        }
        // Release the event
        if (ctx->kevReceive != NULL) {
            ObDereferenceObject(ctx->kevReceive);
        }
        // Free any that were requeued by the VIRQ handler at the last minute
        V4vCancelAllFileIrps(pde, pfo);
        // Free context itself...
        ExFreePoolWithTag(ctx, XENV4V_TAG);
        // Drop the reference the context held that prevents the final close
        ObDereferenceObject(pfo);
    }

    return count;
}

ULONG32
V4vAddRefContext(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG32            count;

    KeAcquireInStackQueuedSpinLock(&pde->contextLock, &lqh);
    count = ++ctx->refc;
    KeReleaseInStackQueuedSpinLock(&lqh);

    return count;
}

VOID
V4vCancelAllFileIrps(XENV4V_EXTENSION *pde, FILE_OBJECT *pfo)
{
    PIRP pendingIrp;
    XENV4V_QPEEK peek;

    peek.types = XENV4V_PEEK_ANY_TYPE; // process for any type
    peek.ops   = XENV4V_PEEK_WRITE;    // and any ops
    peek.pfo   = pfo;                  // for a specific file object

    pendingIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
    while (pendingIrp != NULL) {
        V4vSimpleCompleteIrp(pendingIrp, STATUS_CANCELLED);
        pendingIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
    }
}

VOID
V4vStartConnectionTimer(XENV4V_EXTENSION *pde)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG              count;
    LARGE_INTEGER      due;

    KeAcquireInStackQueuedSpinLock(&pde->timerLock, &lqh);
    count = ++pde->timerCounter;
    KeReleaseInStackQueuedSpinLock(&lqh);

    // Just transitioned from 1
    if (count == 1) {
        due.QuadPart = XENV4V_LARGEINT_DELAY(XENV4V_TIMER_INTERVAL/2);
        KeSetTimerEx(&pde->timer, due, XENV4V_TIMER_INTERVAL, &pde->timerDpc);
    }
}

VOID
V4vStopConnectionTimer(XENV4V_EXTENSION *pde, BOOLEAN immediate)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG              count = (ULONG)-1;

    KeAcquireInStackQueuedSpinLock(&pde->timerLock, &lqh);
    if (immediate) {
        count = pde->timerCounter = 0;
    }
    else if (pde->timerCounter > 0) {
        count = --pde->timerCounter;
    }
    KeReleaseInStackQueuedSpinLock(&lqh);

    // Dropped back to 0, turn off the timer
    if (count == 0) {
        KeCancelTimer(&pde->timer);
    }
}

NTSTATUS V4VInitialize(PCHAR aBuffer, ULONG aInLen, PIO_STACK_LOCATION aStack, PIRP aIrp) {
#if defined(_WIN64)
    if (aInLen == sizeof(V4V_INIT_VALUES_32)) {
        V4V_INIT_VALUES_32 *invs32 = (V4V_INIT_VALUES_32*)aBuffer;
        V4V_INIT_VALUES init;
        init.rxEvent = invs32->rxEvent;
        init.ringLength = invs32->ringLength;
        V4V_INIT_VALUES *invs = &init;
#else
    if (aInLen == sizeof(V4V_INIT_VALUES)) {
        V4V_INIT_VALUES *invs = (V4V_INIT_VALUES*)aBuffer;
#endif
        XENV4V_CONTEXT *ctx = (XENV4V_CONTEXT*)aStack->FileObject->FsContext;
        NTSTATUS status;
        if (ctx == NULL) {
            Error("no file context!\n");
            return STATUS_INVALID_HANDLE;
        }

        if (invs->rxEvent == NULL) {
            Error("no event handle!\n");
            return STATUS_INVALID_HANDLE;
        }

            // Reference the event objects
            status = ObReferenceObjectByHandle(invs->rxEvent,
                                               EVENT_MODIFY_STATE,
                                               *ExEventObjectType,
                                               aIrp->RequestorMode,
                                               (void **)&ctx->kevReceive,
                                               NULL);

            if (!NT_SUCCESS(status)) {
                Error("failed to get a reference to the receive event - error: 0x%x\n", status);
                return status;
            }

            ctx->ringLength = invs->ringLength;

            // Straighten out the ring
            if (ctx->ringLength > PAGE_SIZE) {
                ctx->ringLength = (ctx->ringLength + XENV4V_RING_MULT - 1) & ~(XENV4V_RING_MULT - 1);
            }
            else {
                ctx->ringLength = PAGE_SIZE; // minimum to guarantee page alignment
            }

            InterlockedExchange(&ctx->state, XENV4V_STATE_IDLE);

            Trace("Success");
        return status;
    }

    Error("Fail2: invalid initialization values.\n");
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS V4VBind(void *aDeviceExtension, PCHAR aBuffer, ULONG aInLen, PIO_STACK_LOCATION aStack) {
    if (aInLen == sizeof(V4V_BIND_VALUES)) {
        V4V_BIND_VALUES *bvs = (V4V_BIND_VALUES*)aBuffer;
        PXENV4V_EXTENSION pde = (PXENV4V_EXTENSION)aDeviceExtension;
        XENV4V_CONTEXT *ctx = (XENV4V_CONTEXT*)aStack->FileObject->FsContext;
        NTSTATUS            status = STATUS_SUCCESS;
        LONG                val;
        KLOCK_QUEUE_HANDLE  lqh;
        XENV4V_RING        *robj;
        uint32_t            port;

        // Use a simple guard variable to enforce the state transition order
        val = InterlockedExchangeAdd(&ctx->state, 0);
        if (val != XENV4V_STATE_IDLE) {
            Warning("state not IDLE, cannot complete bind request\n");
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        ASSERT(ctx->ringObject == NULL);

        if ((bvs->ringId.addr.domain != V4V_DOMID_NONE)&&
                (bvs->ringId.addr.domain != DOMID_INVALID_COMPAT)) {
            Warning("failure - ring ID domain must be V4V_DOMID_NONE - value: 0x%x\n",
                    bvs->ringId.addr.domain);
            return STATUS_INVALID_PARAMETER;
        }

        robj = V4vAllocateRing(ctx->ringLength);
        if (robj == NULL) {
            Error(("failed to allocate the ring\n"));
            return STATUS_NO_MEMORY;
        }

        robj->ring->id = bvs->ringId;

        // Have to grab this outside of lock at IRQL PASSIVE
        port = V4vRandomPort(pde);

        // Lock this section since we access the list
        KeAcquireInStackQueuedSpinLock(&pde->ringLock, &lqh);

        if (robj->ring->id.addr.port == V4V_PORT_NONE) {
            robj->ring->id.addr.port = V4vSparePortNumber(pde, port);
        }
        else if (V4vRingIdInUse(pde, &robj->ring->id)) {
            KeReleaseInStackQueuedSpinLock(&lqh);
            Warning("ring ID already in use, cannot bind\n");
            V4vReleaseRing(pde, ctx->ringObject);
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        // Now register the ring.
        status = V4vRegisterRing(robj);
        if (!NT_SUCCESS(status)) {
            KeReleaseInStackQueuedSpinLock(&lqh);
            Error("failed in register ring hypercall - error: 0x%x\n", status);
            V4vReleaseRing(pde, ctx->ringObject);
            return status;
        }
        robj->registered = TRUE;

        // Link it to the main list and set our pointer to it
        V4vLinkToRingList(pde, robj);
        ctx->ringObject = robj;

        KeReleaseInStackQueuedSpinLock(&lqh);

        InterlockedExchange(&ctx->type, XENV4V_TYPE_DATAGRAM);
        InterlockedExchange(&ctx->state, XENV4V_STATE_BOUND);

        Trace("Success\n");

        return status;
    }

    Error("Fail2: invalid bind values.\n");
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS V4VListen(PCHAR aBuffer, ULONG aInLen, PIO_STACK_LOCATION aStack) {
    if (aInLen == sizeof(V4V_LISTEN_VALUES)) {
        V4V_LISTEN_VALUES *lvs = (V4V_LISTEN_VALUES*)aBuffer;
        XENV4V_CONTEXT *ctx = (XENV4V_CONTEXT*)aStack->FileObject->FsContext;
        LONG    val;
        ULONG32 size;

        val = InterlockedExchangeAdd(&ctx->state, 0);
        if (val != XENV4V_STATE_BOUND) {
            Error("state not BOUND, cannot complete connect listen\n");
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        if (lvs->backlog > V4V_SOMAXCONN) {
            Error("backlog cannot be larger than V4V_SOMAXCONN: %d\n", V4V_SOMAXCONN);
            return STATUS_INVALID_PARAMETER;
        }

        // Initialize the listener specific pieces of the context
        KeInitializeSpinLock(&ctx->u.listener.synLock);
        ctx->u.listener.synHead = NULL;
        ctx->u.listener.synTail = NULL;
        ctx->u.listener.synCount = 0;
        if (lvs->backlog == 0) {
            ctx->u.listener.backlog = V4V_SOMAXCONN;
        }
        else {
            ctx->u.listener.backlog = (LONG)lvs->backlog;
        }
        size = ctx->u.listener.backlog*sizeof(XENV4V_SYN);

        ctx->u.listener.synList = (XENV4V_SYN*)ExAllocatePoolWithTag(NonPagedPool, size, XENV4V_TAG);
        if (ctx->u.listener.synList == NULL) {
            Error("listen failed, out of memory\n");
            return STATUS_NO_MEMORY;
        }
        RtlZeroMemory(ctx->u.listener.synList, size);

        // Now it becomes a listener type for ever more
        InterlockedExchange(&ctx->type, XENV4V_TYPE_LISTENER);

        // After this transition the ring is ready to receive SYNs for new connections
        InterlockedExchange(&ctx->state, XENV4V_STATE_LISTENING);

        Trace("Success\n");

        return STATUS_SUCCESS;
    }

    Error("Fail2: invalid listen values.\n");
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS V4VAccept(void *aDeviceExtension, PCHAR aBuffer, ULONG aInLen, PIO_STACK_LOCATION aStack, PIRP aIrp) {
    PXENV4V_EXTENSION pde = (PXENV4V_EXTENSION)aDeviceExtension;
    XENV4V_CONTEXT *ctx = (XENV4V_CONTEXT*)aStack->FileObject->FsContext;
    ULONG ioControlCode = aStack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS            status = STATUS_SUCCESS;
    LONG                val;
    V4V_INIT_VALUES     init;
    FILE_OBJECT        *pfo = NULL;
    XENV4V_CONTEXT     *actx;
    XENV4V_INSERT       ins = {FALSE};
    HANDLE              fh;
    HANDLE              rxe;
    V4V_ACCEPT_PRIVATE *priv;

    val = InterlockedExchangeAdd(&ctx->state, 0);
    if (val != XENV4V_STATE_LISTENING) {
        Error("state not LISTENING, cannot complete accept request\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // Handle 32b/64b thunk sructures here and test input
#if defined(_WIN64)
    if (ioControlCode == V4V_IOCTL_ACCEPT_32)
    {
        V4V_ACCEPT_VALUES_32 *avs32 = (V4V_ACCEPT_VALUES_32*)aBuffer;

        if (aInLen != sizeof(V4V_ACCEPT_VALUES_32)) {
            Error("invalid accept values.\n");
            return STATUS_INVALID_PARAMETER;
        }
        fh  = avs32->fileHandle;
        rxe = avs32->rxEvent;
        priv = (V4V_ACCEPT_PRIVATE*)((UCHAR*)avs32 + FIELD_OFFSET(V4V_ACCEPT_VALUES_32, priv));
    }
    else
#endif
    {
        V4V_ACCEPT_VALUES *avs = (V4V_ACCEPT_VALUES*)aBuffer;

        UNREFERENCED_PARAMETER(ioControlCode);

        if (aInLen != sizeof(V4V_ACCEPT_VALUES)) {
            Error("invalid accept values.\n");
            return STATUS_INVALID_PARAMETER;
        }
        fh  = avs->fileHandle;
        rxe = avs->rxEvent;
        priv = (V4V_ACCEPT_PRIVATE*)((UCHAR*)avs + FIELD_OFFSET(V4V_ACCEPT_VALUES, priv));
    }

    // Any IRPs that are queued are given a sanity initialization
    V4vInitializeIrp(aIrp);

    // Get a reference to the file object for the handle
    status = ObReferenceObjectByHandle(fh,
                                       0,
                                       *IoFileObjectType,
                                       aIrp->RequestorMode,
                                       &pfo,
                                       NULL);
    if (!NT_SUCCESS(status)) {
        Error("failed to get a reference to the accepter file object - error: 0x%x\n", status);
        return status;
    }
    actx = (XENV4V_CONTEXT*)pfo->FsContext;
    ObDereferenceObject(pfo);

    // Store the referenced acceptor context in the IOCTL buffer so we can access it at > PASSIVE later.
    V4vAddRefContext(pde, actx);
#if defined(_WIN64)
    priv->q.a = (ULONG64)actx;
#else
    priv->d.a = (ULONG32)actx;
#endif

    // Do the base initialization of the file object context
    init.rxEvent = rxe;
    init.ringLength = ctx->ringLength; // shared ring length
    status = V4vCtrlInitializeFile(actx, &init, aIrp);
    if (!NT_SUCCESS(status)) {
        V4vReleaseContext(pde, actx, TRUE);
        Error("failed to initialize the accepter file object - error: 0x%x\n", status);
        return status;
    }

    // Now initialize the accepter specific state and associate the accepter
    // with the listener context and ring.
    KeInitializeSpinLock(&actx->u.accepter.dataLock);
    actx->u.accepter.dataList = NULL;
    actx->u.accepter.dataTail = NULL;
    V4vAddRefContext(pde, ctx);
    V4vAddRefRing(pde, ctx->ringObject);
    actx->u.accepter.listenerContext = ctx;
    actx->ringObject = ctx->ringObject;

    // Now it becomes an accepter type for ever more
    InterlockedExchange(&actx->type, XENV4V_TYPE_ACCEPTER);

    // After this transition, we will wait for a SYN (may be one in the queue already).
    InterlockedExchange(&actx->state, XENV4V_STATE_ACCEPTING);

    // Flag it
    aIrp->Tail.Overlay.DriverContext[0] =
        (PVOID)(ULONG_PTR)(XENV4V_PEEK_STREAM|XENV4V_PEEK_ACCEPT|XENV4V_PEEK_IOCTL);

    // Always queue it to the back and marks it pending. If it fails to be queued then
    // the user mode call will close the new handle.
    status = IoCsqInsertIrpEx(&pde->csqObject, aIrp, NULL, &ins);
    if (NT_SUCCESS(status)) {
        status = STATUS_PENDING;
        // Drive any accepts
        V4vDoAccepts(pde, ctx);
    }

    return status;
}

NTSTATUS V4VConnect(void *aDeviceExtension, PCHAR aBuffer, ULONG aInLen, PIO_STACK_LOCATION aStack, PIRP aIrp) {
    if (aInLen == sizeof(V4V_CONNECT_VALUES)) {
        V4V_CONNECT_VALUES *cvs = (V4V_CONNECT_VALUES*)aBuffer;
        PXENV4V_EXTENSION pde = (PXENV4V_EXTENSION)aDeviceExtension;
        XENV4V_CONTEXT *ctx = (XENV4V_CONTEXT*)aStack->FileObject->FsContext;

        NTSTATUS      status = STATUS_SUCCESS;
        LONG          val;
        XENV4V_INSERT ins = {FALSE};

        val = InterlockedExchangeAdd(&ctx->state, 0);
        if (val != XENV4V_STATE_BOUND) {
            Error("state not BOUND, cannot complete connect request\n");
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        // Any IRPs that are queued are given a sanity initialization
        V4vInitializeIrp(aIrp);

        // These stream related values are only set once during a single phase of transitioning
        // to a stream type.
        ctx->sdst = cvs->ringAddr;
        ctx->connId = (ULONG64)(RtlRandomEx(&pde->seed) & 0xffffffff);

        // Update the stream header in the IRPs buffer. The cvs pointer points to the IRPs actual
        // in/out buffer the IOCTL is defined to have output.
        cvs->sh.flags = V4V_SHF_SYN;
        cvs->sh.conid = (ULONG32)ctx->connId;

        // Now it becomes a connector type for ever more
        InterlockedExchange(&ctx->type, XENV4V_TYPE_CONNECTOR);

        // After this transition, we will still send a SYN datagram and get the ACK
        InterlockedExchange(&ctx->state, XENV4V_STATE_CONNECTING);

        // Start the connecting timer each time a context goes into this state.
        V4vStartConnectionTimer(pde);

        // Flag it
        aIrp->Tail.Overlay.DriverContext[0] =
            (PVOID)(ULONG_PTR)(XENV4V_PEEK_STREAM|XENV4V_PEEK_WRITE|XENV4V_PEEK_SYN|XENV4V_PEEK_IOCTL);

        // Always queue it to the back and marks it pending
        status = IoCsqInsertIrpEx(&pde->csqObject, aIrp, NULL, &ins);
        if (NT_SUCCESS(status)) {
            status = STATUS_PENDING;
            // Drive any write IO
            V4vProcessContextWrites(pde, ctx);
        }
        else {
            // Fail it in IOCTL routine and return go to disconnected state
            V4vStopConnectionTimer(pde, FALSE);
            InterlockedExchange(&ctx->state, XENV4V_STATE_DISCONNECTED);
        }

        return status;
    }

    Error("Fail2: invalid connect values.\n");
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS V4VConnectWait(void *aDeviceExtension, PCHAR aBuffer, ULONG aInLen, PIO_STACK_LOCATION aStack, PIRP aIrp) {
    if (aInLen == sizeof(V4V_WAIT_VALUES)) {
        V4V_WAIT_VALUES *wvs = (V4V_WAIT_VALUES*)aBuffer;
        PXENV4V_EXTENSION pde = (PXENV4V_EXTENSION)aDeviceExtension;
        XENV4V_CONTEXT *ctx = (XENV4V_CONTEXT*)aStack->FileObject->FsContext;
        NTSTATUS      status = STATUS_SUCCESS;
        LONG          val;
        XENV4V_INSERT ins = {FALSE};

        // This is the connect wait functionality that allows a single end to end
        // stream connection. This part serves as the "listening" end.
        val = InterlockedExchangeAdd(&ctx->state, 0);
        if (val != XENV4V_STATE_BOUND) {
            Error("state not BOUND, cannot complete connect wait request\n");
            return STATUS_INVALID_DEVICE_REQUEST;
        }

        // Any IRPs that are queued are given a sanity initialization
        V4vInitializeIrp(aIrp);

        // Update the stream header in the IRPs buffer. Just clear if now, later it will
        // be used for the ACK.
        wvs->sh.flags = 0;
        wvs->sh.conid = 0;

        // Now it becomes a connector type for ever more
        InterlockedExchange(&ctx->type, XENV4V_TYPE_CONNECTOR);

        // After this transition, we will wait to get a SYN and send back the ACK
        InterlockedExchange(&ctx->state, XENV4V_STATE_WAITING);

        // Flag it
        aIrp->Tail.Overlay.DriverContext[0] =
            (PVOID)(ULONG_PTR)(XENV4V_PEEK_STREAM|XENV4V_PEEK_READ|XENV4V_PEEK_SYN|XENV4V_PEEK_IOCTL);

        // Always queue it to the back and marks it pending
        status = IoCsqInsertIrpEx(&pde->csqObject, aIrp, NULL, &ins);
        if (NT_SUCCESS(status)) {
            status = STATUS_PENDING;
            // Drive any read IO
            V4vProcessContextReads(pde, ctx);
        }
        else {
            // Fail it in IOCTL routine and return go to disconnected state
            InterlockedExchange(&ctx->state, XENV4V_STATE_DISCONNECTED);
        }

        return status;
    }

    Error("Fail2: invalid connect wait values.\n");
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS V4VGetInfo(PCHAR aBuffer, ULONG aInLen, PIO_STACK_LOCATION aStack) {
    if (aInLen == sizeof(V4V_GETINFO_VALUES)) {
        V4V_GETINFO_VALUES *gi = (V4V_GETINFO_VALUES*)aBuffer;
        XENV4V_CONTEXT *ctx = (XENV4V_CONTEXT*)aStack->FileObject->FsContext;
        NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
        LONG               val;
        KLOCK_QUEUE_HANDLE lqh;

        val = InterlockedExchangeAdd(&ctx->state, 0);

        if (gi->type == V4vGetPeerInfo) {
            if (val & (XENV4V_STATE_CONNECTING|XENV4V_STATE_CONNECTED|XENV4V_STATE_ACCEPTED)) {
                RtlMoveMemory(&gi->ringInfo.addr, &ctx->sdst, sizeof(v4v_addr_t));
                gi->ringInfo.partner = V4V_DOMID_NONE;
                status = STATUS_SUCCESS;
            }
        }
        else if (gi->type == V4vGetLocalInfo) {
            if (val & (XENV4V_STATE_BOUND|XENV4V_STATE_LISTENING|XENV4V_STATE_WAITING|
                       XENV4V_STATE_CONNECTING|XENV4V_STATE_CONNECTED|
                       XENV4V_STATE_ACCEPTED)) {
                KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);
                RtlMoveMemory(&gi->ringInfo, &ctx->ringObject->ring->id, sizeof(v4v_ring_id_t));
                KeReleaseInStackQueuedSpinLock(&lqh);
                status = STATUS_SUCCESS;
            }
        }

        return status;
    }

    Error("Fail2: invalid get info values.\n");
    return STATUS_INVALID_PARAMETER;
}

NTSTATUS V4VDisconnect(void *aDeviceExtension, PIO_STACK_LOCATION aStack) {
    PXENV4V_EXTENSION pde = (PXENV4V_EXTENSION)aDeviceExtension;
    XENV4V_CONTEXT *ctx = (XENV4V_CONTEXT*)aStack->FileObject->FsContext;
    LONG val;

    val = InterlockedExchangeAdd(&ctx->state, 0);
    if ((val & (XENV4V_STATE_CONNECTED|XENV4V_STATE_ACCEPTED)) == 0) {
        // Drop the warning - it is fine if a client calls disconnect event though it did not connect.
        Trace("state not CONNECTED or ACCEPTED, cannot complete disconnect request\n");
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // Send a RST write. This may go out immediately or get queued.
    V4vSendReset(pde, ctx, (uint32_t)ctx->connId, &ctx->sdst, FALSE);

    // Flush any queued inbound data
    if (val == XENV4V_STATE_ACCEPTED) {
        V4vFlushAccepterQueueData(ctx);
    }

    // Disconnect our side. Note that if the client is doing an orderly shutdown
    // then it does not need to be signaled and presumably has canceled all its
    // IO to. Worst case any IO will be cleaned up in the final release of the
    // context so just transition the state.
    InterlockedExchange(&ctx->state, XENV4V_STATE_DISCONNECTED);

    return STATUS_SUCCESS;
}

NTSTATUS V4VDumpRing(PIO_STACK_LOCATION aStack) {
    XENV4V_CONTEXT *ctx = (XENV4V_CONTEXT*)aStack->FileObject->FsContext;
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    LONG               val;
    KLOCK_QUEUE_HANDLE lqh;

    val = InterlockedExchangeAdd(&ctx->state, 0);

    if (val & (XENV4V_STATE_BOUND|XENV4V_STATE_LISTENING|XENV4V_STATE_WAITING|
               XENV4V_STATE_CONNECTING|XENV4V_STATE_CONNECTED|
               XENV4V_STATE_ACCEPTED)) {
        KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);
        V4vDumpRing(ctx->ringObject->ring);
        KeReleaseInStackQueuedSpinLock(&lqh);
        status = STATUS_SUCCESS;
    }

    return status;
}

