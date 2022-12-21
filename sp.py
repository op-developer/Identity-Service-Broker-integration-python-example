#!/usr/bin/env python3
#
# Python-based test service provider for OP Identity Service Broker's OIDC api

import aiohttp
import base64
import binascii
import jinja2
import os
import sanic
import time
import uuid
import datetime
import json

from jwcrypto import jwk, jws, jwe
from jwcrypto.common import json_encode, json_decode


AUTHORIZE_ENDPOINT='https://isb-test.op.fi/oauth/authorize'
TOKEN_ENDPOINT='https://isb-test.op.fi/oauth/token'
ISBKEY_ENDPOINT='https://isb-test.op.fi/jwks/broker-signed'
ISBEMBEDDED_ENDPOINT='https://isb-test.op.fi/api/embedded-ui/'
ISB_ISS='https://isb-test.op.fi'

CLIENT_ID='saippuakauppias'
FTN_SPNAME=dict(
    fi='Saippuaa kansalle',
    sv='tvål för folket',
    en='Soap for the people'
)
HOSTNAME='localhost'
ALLOWED_ALGS=['RS256',]
ENTITY_EXP_TIME = 90000 # 25 hours

# Global sessions db (in-memory)
sessions = dict()

# Keys
#
# In this example (sandbox) this keypair is fixed.
# In real production environment this value must be replaced with private key which
# is a pair for public key published in JWKS endpoint. ISB get this public key and
# crypt token with public key and in SP side token can be extracted with private key

with open('sandbox-sp-key.pem', 'rb') as dec_key_file:
    decryption_key = jwk.JWK.from_pem(dec_key_file.read())
    decryption_key['use'] = 'enc'

# This key is used to sign payload so that ISB can verify it.
# In this example (sandbox) this keypair is fixed.
# In real production environment ISB fetch public key from JWKS endpoint and check signature

with open('sp-signing-key.pem', 'rb') as sig_key_file:
    signing_key = jwk.JWK.from_pem(sig_key_file.read())
    signing_key['use'] = 'sig'

# This key is used to sign SP Entity Statement and the signed JWKS.
# In this example (sandbox) this keypair is fixed.
# In real production environment ISB verifies the signature agaist the
# public key which is exchanged separately and manually

with open('sandbox-sp-entity-signing-key.pem', 'rb') as entity_key_file:
    entity_signing_key = jwk.JWK.from_pem(entity_key_file.read())
    entity_signing_key['use'] = 'sig'

# This key is is the ISB public Entity Stement signing key.
# In this example (sandbox) this keypair is fixed.
# In real production environment SP verifies the ISB signed JWS signature
# agaist this key. OP will provide the key.

with open('sandbox-isb-entity-signing-pubkey.pem', 'rb') as isb_entity_key_file:
    isb_entity_signing_key = jwk.JWK.from_pem(isb_entity_key_file.read())
    isb_entity_signing_key['use'] = 'sig'


class Session:
    """Session class

    Pass attributes to the constructor as named parameters. Attributes
    can be accessed as class attributes. The session is automatically
    registered in the global in-memory session db object.

    These attributes are automatically generate: sessionid, created
    """

    def __init__(self, **kwargs):
        self.params = kwargs
        if "sessionid" not in self.params:
            self.params['sessionid'] = str(uuid.uuid4())
        if "created" not in self.params:
            self.params['created'] = time.time()
        sessions[self.params['sessionid']] = self

    def __getattribute__(self, key):
        params = object.__getattribute__(self, 'params')
        if key in params:
            return params[key]
        return object.__getattribute__(self, key)


app = sanic.Sanic("python-sp-example")
app.static("/static", "/app/static")

jinja = jinja2.Environment(
    autoescape=True,
    loader=jinja2.FileSystemLoader("/app/templates"),
    )


@app.route("/")
def front_view(req):
    """Front page"""
    template = jinja.get_template('index.html')
    return sanic.response.html(template.render())

@app.route("/embedded")
async def front_view_embedded(req):
    """Front page for embedded mode"""
    embeddedendpoint = ISBEMBEDDED_ENDPOINT + CLIENT_ID + '?lang=en'

    async with aiohttp.ClientSession() as httpSession:
        async with httpSession.get(embeddedendpoint) as apiresp:
            embedded_text = await apiresp.text()
            # handle multi-lines correctly in disturbance notification
            embedded_text = embedded_text.replace(r"\r\n", "<br><br>")
            embedded = json.loads(embedded_text)

    template = jinja.get_template('embedded.html')
    return sanic.response.html(template.render(embedded=embedded))

@app.route("/.well-known/openid-federation")
def entity_statement_view(req):
    # create keyset
    keyset = jwk.JWKSet()
    keyset.add(entity_signing_key)
    # create Entity Statement JSON web token
    openid_relying_party=dict(
        redirect_uris=['https://{0}/oauth/code'.format(HOSTNAME)],
        application_type='web',
        id_token_signed_response_alg='RS256',
        id_token_encrypted_response_alg='RSA-OAEP',
        id_token_encrypted_response_enc='A128CBC-HS256',
        request_object_signing_alg='RS256',
        token_endpoint_auth_method='private_key_jwt',
        token_endpoint_auth_signing_alg='RS256',
        client_registration_types=[],
        organization_name='Saippuakauppias',
        signed_jwks_uri='https://{0}/signed-jwks'.format(HOSTNAME)
    )
    entity_stament = dict(
        iss='https://{0}'.format(HOSTNAME),
        sub='https://{0}'.format(HOSTNAME),
        iat=int(time.time()),
        exp=int(time.time()) + ENTITY_EXP_TIME,
        jwks=dict(keys = []),
        metadata=dict(openid_relying_party=openid_relying_party)
     )
    entity_stament['jwks']=json.loads(keyset.export(False))
    entity_statement_token = jws.JWS(json_encode(entity_stament))
    # sign the Entity Statement JWT
    entity_statement_token.add_signature(
        entity_signing_key,
        alg="RS256",
        protected=json_encode(dict(
            alg='RS256',
            typ='entity-statement+jwt',
            kid=entity_signing_key.thumbprint()
            )))
    return sanic.response.raw(
        entity_statement_token.serialize(True),
        headers={'content-type': 'application/entity-statement+jwt'}
        )

@app.route("/signed-jwks")
def jwks_view(req):
    # create keyset
    keyset = jwk.JWKSet()
    keyset.add(decryption_key)
    keyset.add(signing_key)
    # create JWS
    jwks_to_sign = json_encode(dict(
        keys=json.loads(keyset.export(False)),
        iss='https://{0}'.format(HOSTNAME),
        sub='https://{0}'.format(HOSTNAME),
        iat=int(time.time()),
        exp=int(time.time()) + ENTITY_EXP_TIME
        ))
    jwstoken = jws.JWS(jwks_to_sign)
    # sign it
    jwstoken.add_signature(
        entity_signing_key,
        alg="RS256",
        protected=json_encode(dict(
            alg='RS256',
            kid=entity_signing_key.thumbprint()
            )))
    return sanic.response.raw(
        jwstoken.serialize(True),
        headers={'content-type': 'application/jose'}
        )

@app.route("/authenticate")
def jump_view(req):
    """Jump view linked to from front page. Redirects to Identity Service Broker."""

    idButton = req.args.get('idButton')
    consent = req.args.get('promptBox')
    purpose = req.args.get('purpose')

    template = jinja.get_template('jump.html')

    if idButton is not None:
        session = Session(nonce=binascii.hexlify(os.urandom(10)).decode('ascii'), idButton=idButton, consent=consent, layout='embedded')
        return sanic.response.html(template.render(
            endpoint=AUTHORIZE_ENDPOINT,
            request=make_auth_jwt(session, purpose)
            ))
    else:
        session = Session(nonce=binascii.hexlify(os.urandom(10)).decode('ascii'), consent=consent, layout='')
        return sanic.response.html(template.render(
            endpoint=AUTHORIZE_ENDPOINT,
            request=make_auth_jwt(session, purpose)
            ))

@app.route("/return")
async def return_view(req):
    """Return view for processing authentication results from the Identity Service Broker."""

    code = req.args.get('code')
    error = req.args.get('error')
    sessionid = req.args.get('state')
    error_description = req.args.get('error_description')

    layout = '' # Default value (to be populated with '' or 'embedded')

    if not sessionid or sessionid not in sessions:
        error = error or 'Invalid session'
    else:
        layout = sessions[sessionid].layout

    if error:
        if error=='cancel':
            template = jinja.get_template('cancel.html')
            return sanic.response.html(template.render(error=error, layout=layout))
        else:
            template = jinja.get_template('error.html')
            return sanic.response.html(template.render(error=error, error_description=error_description, layout=layout))

    # Resolve the access code
    async with aiohttp.ClientSession() as httpSession:
        data = aiohttp.FormData()
        data.add_field('code', code)
        data.add_field('redirect_uri', 'https://{0}/return'.format(HOSTNAME))
        data.add_field('grant_type', 'authorization_code')
        data.add_field('client_assertion', make_token_jwt())
        data.add_field('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')

        headers=dict(
            Accept='application/json'
            )

        async with httpSession.post(TOKEN_ENDPOINT, data=data, headers=headers) as tokenresp:
            token_data = await tokenresp.text()

        try:
            id_token = json_decode(token_data)['id_token']
        except KeyError:
            raise ValueError(token_data)

        jwetoken = jwe.JWE()
        jwetoken.deserialize(id_token)
        jwetoken.decrypt(decryption_key)

        jwstoken = jws.JWS()
        jwstoken.allowed_algs = ALLOWED_ALGS
        jwstoken.deserialize(jwetoken.payload.decode('ascii'))

        sig_key = jwstoken.jose_header['kid']

        async with aiohttp.ClientSession() as httpSession:
            async with httpSession.get(ISBKEY_ENDPOINT) as jwks_resp:
                try:
                    # jwks_resp is a signed JSON web token
                    signed_jwks_token = jws.JWS()
                    signed_jwks_token.deserialize(await jwks_resp.text())
                    jwks_payload = json.loads(signed_jwks_token.objects['payload'])
                except:
                    raise Exception("processing of signed JWKS JWS failed")
                try:
                    # create keyset
                    keyset = jwk.JWKSet()
                    keyset.add(isb_entity_signing_key)
                    # verify the signature with the ISB public entity key
                    signed_jwks_token.verify(keyset)
                except:
                    raise Exception("Verifying the signed JWKS signature failed")
                # Verify ISS and SUB
                if (jwks_payload['iss'] != jwks_payload['sub'] or jwks_payload['iss'] != ISB_ISS ):
                    raise Exception("Verifying the ISS or SUB failed")
                # verify IAT and EXP
                now = time.time()
                iat = jwks_payload['iat']
                exp = jwks_payload['exp']
                if not (iat <= now < exp):
                    raise Exception("Verifying IAT and EXP failed")


        for key in  jwks_payload['keys']:
            kid = key['kid']
            if kid==sig_key:
                isb_cert=jwk.JWK(**key)

        jwstoken.verify(isb_cert)
        id_token = json_decode(jwstoken.payload)

        date = datetime.datetime.now()
        datestring = date.strftime("%c")
        variables = repr(id_token)

        if id_token["nonce"]!=sessions[sessionid].nonce:
            error = 'nonce does not match'
            error_description = '{} != {}'.format(id_token["nonce"], sessions[sessionid].nonce)
            template = jinja.get_template('error.html')
            return sanic.response.html(template.render(error=error, error_description=error_description, layout=layout))

        template = jinja.get_template('result.html')
        return sanic.response.html(template.render(variables=variables, id_token=id_token, layout=layout, datestring=datestring))


def make_private_key_jwt(payload):
    """Generate a new compact JWS to identify us to ISB"""
    jwstoken = jws.JWS(payload)
    jwstoken.add_signature(
        signing_key,
        alg="RS256",
        protected=json_encode(dict(
            alg='RS256',
            kid=signing_key.thumbprint()
            )))
    return jwstoken.serialize(True)


def make_token_jwt():
    payload = json_encode(dict(
        iss=CLIENT_ID,
        sub=CLIENT_ID,
        aud=AUTHORIZE_ENDPOINT,
        jti=str(uuid.uuid4()),
        exp=int(time.time()) + 600
        ))
    return make_private_key_jwt(payload)


def make_auth_jwt(session, purpose):
    if purpose=='normal':
        purpose = ''

    params = dict(
        client_id=CLIENT_ID,
        redirect_uri='http://{0}/return'.format(HOSTNAME),
        nonce=session.nonce,
        state=session.sessionid,
        scope="openid profile personal_identity_code " + purpose,
        response_type="code",
        ftn_spname=FTN_SPNAME['en']
        )

    if session.consent=='consent':
        params['prompt'] = 'consent'

    if session.layout=='embedded':
        params['ftn_idp_id'] = session.idButton

    payload = json_encode(params)

    return make_private_key_jwt(payload)


if __name__=='__main__':
    app.run(host="0.0.0.0", port=3045, debug=False)
