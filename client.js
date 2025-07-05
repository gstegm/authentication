const registerForm = document.getElementById('register-form');
const loginForm = document.getElementById('login-form');

async function registerStart() {
  try {
    const response = await fetch('http://localhost:5000/register/start');
    
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    
    return (await response.json());  // Parse the response as JSON

  } catch (error) {
    console.error('There was a problem with your fetch operation:', error);
  }
}


async function registerFinish(credentials) {
  try {
    // Make the POST request
    const response = await fetch('http://localhost:5000/register/finish', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',  // Indicate that we are sending JSON
      },
      body: JSON.stringify(credentials)  // Convert the data object into JSON string
    });

    // Check if the response is ok (status code 2xx)
    if (!response.ok) {
      throw new Error(`Network response was not ok: ${response.statusText}`);
    }

    // Parse the response as JSON
    const responseData = await response.json();
    
    // Return the parsed data
    return responseData;
  } catch (error) {
    // Handle any errors (network errors, JSON errors, etc.)
    console.error('There was a problem with your fetch operation:', error);
    throw error;  // Re-throw if you want to handle it elsewhere
  }
}

async function register(event) {
  event.preventDefault();
  const username = document.getElementById('username1').value.trim();
  if (!username) return alert('Please enter a username');

  try {
    const optionsFormatted = formatRegisterOptions(await registerStart());
    const credentials = await navigator.credentials.create({publicKey: optionsFormatted});
    const credentialsFormatted = formatRegisterCredentials(credentials);
    registerFinish(credentialsFormatted);
  } catch (err) {
    console.error("Registration error:", err);
  }
}


async function loginStart() {
  try {
    const response = await fetch('http://localhost:5000/login/start');
    
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    
    return (await response.json());  // Parse the response as JSON

  } catch (error) {
    console.error('There was a problem with your fetch operation:', error);
  }
}


async function loginFinish(credentials) {
  try {
    // Make the POST request
    const response = await fetch('http://localhost:5000/login/finish', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',  // Indicate that we are sending JSON
      },
      body: JSON.stringify(credentials)  // Convert the data object into JSON string
    });

    // Check if the response is ok (status code 2xx)
    if (!response.ok) {
      throw new Error(`Network response was not ok: ${response.statusText}`);
    }

    // Parse the response as JSON
    const responseData = await response.json();
    
    // Return the parsed data
    return responseData;
  } catch (error) {
    // Handle any errors (network errors, JSON errors, etc.)
    console.error('There was a problem with your fetch operation:', error);
    throw error;  // Re-throw if you want to handle it elsewhere
  }
}


async function login(event) {
  event.preventDefault();
  const username = document.getElementById('username1').value.trim();
  if (!username) return alert('Please enter a username');

  try {
    const optionsFormatted = formatLoginOptions(await loginStart());
    const credentials = await navigator.credentials.get({publicKey: optionsFormatted});
    const credentialsFormatted = formatLoginCredentials(credentials);
    loginFinish(credentialsFormatted);
  } catch (err) {
    console.error("Registration error:", err);
  }
}

function formatRegisterOptions(options) {
  return {
    rp: options.rp,
    user: {
      id: base64URLStringToBuffer(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName
    },
    challenge: base64URLStringToBuffer(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams,
    excludeCredentials: options.excludeCredentials,
    attestation: options.attestation,
  }
}

function formatRegisterCredentials(credentials) {
  return {
    id: credentials.id,
    rawId: bufferToBase64URLString(credentials.rawId),
    response: {
      attestationObject: bufferToBase64URLString(credentials.response.attestationObject),
      clientDataJSON: bufferToBase64URLString(credentials.response.clientDataJSON),
      transports: credentials.response.transports,
    },
    type: credentials.type,
    clientExtensionResults: credentials.clientExtensionResults,
    authenticatorAttachment: credentials.authenticatorAttachment
  }
}

function formatLoginCredentials(credentials) {
  return {
    id: credentials.id,
    rawId: bufferToBase64URLString(credentials.rawId),
    response: {
      authenticatorData: bufferToBase64URLString(credentials.response.authenticatorData),
      clientDataJSON: bufferToBase64URLString(credentials.response.clientDataJSON),
      signature: bufferToBase64URLString(credentials.response.signature),
      userHandle: bufferToBase64URLString(credentials.response.userHandle),
    },
    type: credentials.type,
    authenticatorAttachment: credentials.authenticatorAttachment,
    clientExtensionResults: {},
  }
}

function formatLoginOptions(options) {
  return {
    rpId: options.rpId,
    challenge: base64URLStringToBuffer(options.challenge),
    timeout: options.timeout,
    allowCredentials: [{
      type: options.allowCredentials[0].type,
      id: base64URLStringToBuffer(options.allowCredentials[0].id),
    }],
    userVerification: options.userVerification,
  }
}

function bufferToBase64URLString(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const charCode of bytes) {
        str += String.fromCharCode(charCode);
    }
    const base64String = btoa(str);
    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLStringToBuffer(base64URLString) {
    const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLength, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
}

registerForm.addEventListener('submit', register);
loginForm.addEventListener('submit', login);