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
import base64, traceback


app = Flask(__name__)



################
#
# Examples of using webauthn for registration ceremonies
#
################

# Simple Options

challenge_bytes=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
public_key = []
credential_ids = []

complex_registration_options = generate_registration_options(
    rp_id="localhost",
    rp_name="Example Co",
    user_id=bytes([1, 2, 3, 4]),
    user_name="lee",
    user_display_name="Lee",
    attestation=AttestationConveyancePreference.DIRECT,
    authenticator_selection=AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        resident_key=ResidentKeyRequirement.REQUIRED,
    ),
    challenge=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
    exclude_credentials=[
        PublicKeyCredentialDescriptor(id=b"1234567890"),
    ],
    timeout=12000,
    hints=[PublicKeyCredentialHint.CLIENT_DEVICE],
)



@app.route('/register/start')
def registerStart():
    # Sample data to send as JSON response
    data = options_to_json(complex_registration_options)
    return data


@app.route('/register/finish', methods=['POST'])
def registerFinish():
    try:
        # Get JSON data from the request
        data = request.get_json()

        rawId = data['rawId']
        rawId_base64url = base64.urlsafe_b64encode(bytes(list(rawId.values()))).rstrip(b'=').decode('utf-8')
        data['rawId'] = rawId_base64url

        client_data_json = data['response']['clientDataJSON']
        client_data_json_base64url = base64.urlsafe_b64encode(bytes(list(client_data_json.values()))).rstrip(b'=').decode('utf-8')
        data['response']['clientDataJSON'] = client_data_json_base64url

        attestation_object = data['response']['attestationObject']
        attestation_object_base64url = base64.urlsafe_b64encode(bytes(list(attestation_object.values()))).rstrip(b'=').decode('utf-8')
        data['response']['attestationObject'] = attestation_object_base64url

        # Check if the data was received
        if not data:
            return jsonify({"error": "No data provided"}), 400

        registration_verification = verify_registration_response(
        # Demonstrating the ability to handle a plain dict version of the WebAuthn response
        credential= data,
        expected_challenge=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
        expected_origin="http://localhost:5500",
        expected_rp_id="localhost",
        require_user_verification=True,
        )
        public_key.append(registration_verification.credential_public_key)
        credential_ids.append(data['id'])
        assert(registration_verification.credential_id == base64url_to_bytes(data['id']))
        return {'status': 'success'}, 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route('/login/start')
def loginStart():

    complex_authentication_options = generate_authentication_options(
        rp_id="localhost",
        challenge=b"1234567890",
        timeout=12000,
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_ids[0]))],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    # Sample data to send as JSON response
    data = options_to_json(complex_authentication_options)
    return data


@app.route('/login/finish', methods=['POST'])
def loginFinish():
    try:
        # Get JSON data from the request
        data = request.get_json()

        rawId = data['rawId']
        rawId_base64url = base64.urlsafe_b64encode(bytes(list(rawId.values()))).rstrip(b'=').decode('utf-8')
        data['rawId'] = rawId_base64url

        authenticator_data = data['response']['authenticatorData']
        authenticator_data_base64url = base64.urlsafe_b64encode(bytes(list(authenticator_data.values()))).rstrip(b'=').decode('utf-8')
        data['response']['authenticatorData'] = authenticator_data_base64url

        client_data_json = data['response']['clientDataJSON']
        client_data_json_base64url = base64.urlsafe_b64encode(bytes(list(client_data_json.values()))).rstrip(b'=').decode('utf-8')
        data['response']['clientDataJSON'] = client_data_json_base64url

        signature = data['response']['signature']
        signature_base64url = base64.urlsafe_b64encode(bytes(list(signature.values()))).rstrip(b'=').decode('utf-8')
        data['response']['signature'] = signature_base64url
        
        user_handle = data['response']['userHandle']
        user_handle_base64url = base64.urlsafe_b64encode(bytes(list(user_handle.values()))).rstrip(b'=').decode('utf-8')
        data['response']['userHandle'] = user_handle_base64url

        # Check if the data was received
        if not data:
            return jsonify({"error": "No data provided"}), 400

        print(public_key[0])
        authentication_verification = verify_authentication_response(
        # Demonstrating the ability to handle a plain dict version of the WebAuthn response
        credential= data,
        expected_challenge=b"1234567890",
        expected_origin="http://localhost:5500",
        expected_rp_id="localhost",
        credential_public_key=public_key[0],
        credential_current_sign_count=0,
        require_user_verification=True,
        )

        return {'status': 'success'}, 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)