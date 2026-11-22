import os
import re
import decimal
import stripe


def _json_safe(value):
    """Recursively turn a Stripe object/structure into JSON-serializable data.

    `stripe.checkout.Session.list_line_items` returns rich `LineItem` objects
    whose `to_dict()` can contain `Decimal` values; both are rejected by Flask's
    `jsonify`. This normalizes everything to plain dict/list/str/number so the
    legitimate "checkout lines" feature keeps working after the D3 fix.
    """
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, decimal.Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value

# A valid Stripe Checkout Session id looks like `cs_test_...` / `cs_live_...`.
# Validating it before building the API URL prevents an attacker from turning
# the `checkout_session_id` parameter into an SSRF that leaks the Stripe API
# key to an arbitrary host (e.g. `@attacker.com/`) (D3).
CHECKOUT_SESSION_ID_RE = re.compile(r'^cs_(test|live)_[A-Za-z0-9]+$')

def create_checkout(reference, name, unit_price, quantity, confirmation_secret):
    """
        Create Stripe checkout
        Documentation: https://docs.stripe.com/checkout/quickstart?client=react&lang=python
    """
    
    stripe.api_key = os.getenv('STRIPE_API_KEY')
    origin_host = os.getenv('APP_ORIGIN_HOST')
    return stripe.checkout.Session.create(
        mode='payment',
        success_url=f"{origin_host}/booking/{reference}?checkout_confirmation_secret={confirmation_secret}",
        cancel_url=origin_host,
        line_items=[
            {
                'quantity': quantity,
                'price_data': {
                    'currency': 'EUR',
                    'unit_amount': round(unit_price * 100),
                    'product_data': {
                        'name': name,
                    },
                },
            },
        ],
    )

def get_checkout_lines(checkout_session_id):
    # D3 fix: reject any value that is not a well-formed Stripe session id so
    # the API host/path can never be manipulated by the caller.
    if not checkout_session_id or not CHECKOUT_SESSION_ID_RE.match(checkout_session_id):
        raise ValueError("Invalid checkout session id")

    stripe.api_key = os.getenv('STRIPE_API_KEY')
    line_items = stripe.checkout.Session.list_line_items(checkout_session_id)
    return [_json_safe(item) for item in line_items["data"]]
