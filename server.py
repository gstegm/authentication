from flask import Flask, jsonify, request
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
import base64, traceback, os, uuid


app = Flask(__name__)


public_keys = {}
credential_ids = {}
challenges = {}
userids = {}


@app.route('/register/start', methods=['POST'])
def register_start():
    data = request.get_json()
    username = data['username']
    print(username)
    challenge_gen = os.urandom(32)
    challenges[username] = challenge_gen
    userid_gen = uuid.uuid4().bytes
    userids[username] = userid_gen
    complex_registration_options = generate_registration_options(
        rp_id="localhost",
        rp_name="GM Authentication",
        user_id=userid_gen,
        user_name=username,
        user_display_name=username,
        attestation=AttestationConveyancePreference.DIRECT,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
        ),
        challenge=challenge_gen,
        # exclude_credentials=[
        #     PublicKeyCredentialDescriptor(id=b"1234567890"),
        # ],
        timeout=12000,
        hints=[PublicKeyCredentialHint.CLIENT_DEVICE],
    )
    return options_to_json(complex_registration_options)


@app.route('/register/finish', methods=['POST'])
def register_finish():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        username = data['username']
        credentials = data['credentials']
        registration_verification = verify_registration_response(
            credential= credentials,
            expected_challenge=challenges[username],
            expected_origin="http://localhost:5500",
            expected_rp_id="localhost",
            require_user_verification=True,
        )
        public_keys[credentials['id']] = registration_verification.credential_public_key
        if username not in credential_ids:
            credential_ids[username] = []
        credential_ids[username].append(credentials['id'])
        assert(registration_verification.credential_id == base64url_to_bytes(credentials['id']))
        return {'status': 'success'}, 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/login/start')
def login_start():
    try:
        username = request.get_json()
        challenge_gen = os.urandom(32)
        challenges[username] = challenge_gen
        complex_authentication_options = generate_authentication_options(
            rp_id="localhost",
            challenge=challenge_gen,
            timeout=12000,
            allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_ids[username]))],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return options_to_json(complex_authentication_options)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/login/finish', methods=['POST'])
def login_finish():
    try:
        credentials = request.get_json()
        if not credentials:
            return jsonify({"error": "No data provided"}), 400
        authentication_verification = verify_authentication_response(
            credential= credentials,
            expected_challenge=b"1234567890",
            expected_origin="http://localhost:5500",
            expected_rp_id="localhost",
            credential_public_key=public_keys[credentials['id']],
            credential_current_sign_count=0,
            require_user_verification=True,
        )
        return {'status': 'success'}, 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)