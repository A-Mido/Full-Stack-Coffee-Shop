import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'ask-auth.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee_shop'

# AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Auth Header

'''
@DONE implement get_token_auth_header() method
it should attempt to get the header from the request
..it should raise an AuthError if no header is present
it should attempt to split bearer and the token
..it should raise an AuthError if the header is malformed
return the token part of the header
'''


def get_token_auth_header():
    auth = request.headers.get("Authorization")
    if auth is None:
        raise AuthError({
        'message': 'Authorization header is missing.',
        'description': 'Expected authorization header.'}, 401)

    head_parts = auth.split(' ')
    if len(head_parts) != 2:
        raise AuthError({
        'error': 'Invalid authorization header.',
        'description': 'Expected header must has two parts.'}, 401)

    if head_parts[0].lower() != 'bearer':
        raise AuthError({
        'error': 'Invalid authorization header.',
        'description': 'Authorization header must has a bearer.'}, 401)

    return head_parts[1]

'''
@Done implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

it should raise an AuthError if permissions are not included in the payload
    !!NOTE check your RBAC settings in Auth0
it should raise an AuthError if the requested permission
    string is not in the payload permissions array
return true otherwise
'''


def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
        'error': 'Invalid permission',
        'description': 'Permissions is not included in the payload'}, 400)

    if permission not in payload['permissions']:
        raise AuthError({
        'error': 'Invalid permission',
        'description': 'Permission is not found in the payload'}, 403)

    return True

'''
@DONE implement verify_decode_jwt(token) method
@INPUTS
    token: a json web token (string)

it should be an Auth0 token with key id (kid)
it should verify the token using Auth0 /.well-known/jwks.json
it should decode the payload from the token
it should validate the claims
return the decoded payload

!!NOTE urlopen has a common certificate error described
'''


def verify_decode_jwt(token):

    unverified_header = jwt.get_unverified_header(token)

    if 'kid' not in unverified_header:
        raise AuthError({
        'error': 'Token key is not exist',
        'description': 'Token lacks valid authentication key'}, 401)

    json_url = urlopen(f'http://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwts = json.loads(json_url.read())

    jwts_key = {}
    for key in jwts['keys']:
        if unverified_header['kid'] is key['kid']:
            jwts_key = {
                'kid': key['kid'],
                'kty': key['kty'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    if jwts_key:
        try:
            decoded_payload = jwt.decode(
                token,
                jwts_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f'https://{AUTH0_DOMAIN}/'
            )
            return decoded_payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
            'error': 'Expiered token',
            'description': 'Token is expiered'}, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
            'error': 'Invalid claims',
            'description': 'Please check the claims of '
            'the decode function'}, 401)

        except Exception:
            raise AuthError({
            'error': 'Invalid header',
            'description': 'Unable to parse authentication token'}, 401)

        raise AuthError({
        'error': 'Token error during decoding',
        'description': 'Token is not decoded'}, 401)


'''
@DONE implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

it should use the get_token_auth_header method to get the token
it should use the verify_decode_jwt method to decode the jwt
it should use the check_permissions method validate claims and
..check the requested permission
return the decorator which passes the decoded payload to
..the decorated method
'''


def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
