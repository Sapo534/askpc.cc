"""Community page + sponsor payment verification (USDT on Solana)."""
from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import SOLANA_WALLET
from ..core import limiter, templates
from ..database import get_db
from ..deps import get_current_user, redirect
from ..models import Payment
from ..services.solana import PaymentError, is_valid_signature, verify_usdt_payment
from ..services.sponsors import extend_sponsorship, sponsor_stats

router = APIRouter()


def _page(request: Request, user, db: Session, **extra):
    return templates.TemplateResponse(
        request=request,
        name="community.html",
        context={"user": user, "solana_wallet": SOLANA_WALLET, **sponsor_stats(db), **extra},
    )


@router.get("/community")
@router.get("/community.html")
def community_page(request: Request, db: Session = Depends(get_db)):
    return _page(request, get_current_user(request, db), db)


@router.post("/community/sponsor/verify")
@limiter.limit("10/hour")
def verify_solana_payment(
    request: Request,
    tx_hash: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")

    tx = tx_hash.strip()
    already_claimed = "This transaction signature has already been claimed."

    if not is_valid_signature(tx):
        return _page(request, current_user, db,
                     error="Invalid Solana transaction signature format. Please check the hash.")
    if db.query(Payment).filter(Payment.tx_hash == tx).first():
        return _page(request, current_user, db, error=already_claimed)

    try:
        received = verify_usdt_payment(tx, SOLANA_WALLET, current_user.public_id)
    except PaymentError as err:
        return _page(request, current_user, db, error=str(err))

    db.add(Payment(user_id=current_user.id, tx_hash=tx, amount_usdt=received))
    extend_sponsorship(current_user)
    try:
        db.commit()
    except IntegrityError:  # two parallel requests with the same tx (needs UNIQUE on tx_hash)
        db.rollback()
        return _page(request, current_user, db, error=already_claimed)

    return _page(
        request, current_user, db,
        message="🎉 Payment verified successfully on Solana blockchain! "
        "Sponsor status is active for 30 days.",
    )
