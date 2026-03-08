"""
Stripe webhook handler — receives forwarded events from the gateway
and updates order status in Postgres.
"""
import json
import logging
from fastapi import APIRouter, Request, HTTPException
import db

logger = logging.getLogger("orders-service")
router = APIRouter()


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe events forwarded from the gateway.

    The gateway already verified the Stripe signature, so we trust
    the X-Forwarded-From header here.
    """
    forwarded = request.headers.get("X-Forwarded-From", "")
    if forwarded != "gateway":
        raise HTTPException(status_code=403, detail="must be forwarded from gateway")

    body = await request.body()
    try:
        event = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="invalid JSON")

    event_type = event.get("type", "unknown")
    logger.info(f"Stripe event received: {event_type}")

    if event_type == "checkout.session.completed":
        _handle_checkout_completed(event)
    elif event_type == "payment_intent.succeeded":
        _handle_payment_succeeded(event)
    else:
        logger.info(f"Stripe event {event_type} — no handler")

    return {"received": True, "type": event_type}


def _handle_checkout_completed(event: dict):
    """Mark an order as paid when checkout completes."""
    data = event.get("data", {}).get("object", {})
    order_id = data.get("client_reference_id", "")
    if order_id:
        db.update_order_status(order_id, "paid")
        logger.info(f"Order {order_id} marked as paid (checkout.session.completed)")


def _handle_payment_succeeded(event: dict):
    """Mark an order as paid when a payment intent succeeds."""
    data = event.get("data", {}).get("object", {})
    order_id = data.get("metadata", {}).get("order_id", "")
    if order_id:
        db.update_order_status(order_id, "paid")
        logger.info(f"Order {order_id} marked as paid (payment_intent.succeeded)")
