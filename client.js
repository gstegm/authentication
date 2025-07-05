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
    const options = await registerStart();
    const optionsFormatted = formatOptions(options);
    const credentials = await navigator.credentials.create({publicKey: optionsFormatted});
    const credentialsFormatted = formatCredentials(credentials);
    console.log(credentialsFormatted);
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
    const options = await loginStart();
    console.log("options", options);
    const optionsFormatted = formatLoginOptions(options);
    console.log("optionsFormatted: ", optionsFormatted);
    const credentials = await navigator.credentials.get({publicKey: optionsFormatted});
    const credentialsFormatted = formatLoginCredentials(credentials);
    console.log("credentialsFormatted: ", credentialsFormatted);
    loginFinish(credentialsFormatted);
  } catch (err) {
    console.error("Registration error:", err);
  }
}

function base64urlToUint8Array(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const binaryString = atob(base64);
  const uint8Array = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    uint8Array[i] = binaryString.charCodeAt(i);
  }
  return uint8Array;
}

function formatOptions(options) {
  return {
    rp: options.rp,
    user: {
      id: base64urlToUint8Array(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName
    },
    challenge: base64urlToUint8Array(options.challenge),
    pubKeyCredParams: options.pubKeyCredParams,
    excludeCredentials: options.excludeCredentials,
    attestation: options.attestation,
  }
}

function formatCredentials(credentials) {
  return {
    id: credentials.id,
    rawId: credentials.rawId,
    response: {
      attestationObject: credentials.response.attestationObject,
      clientDataJSON: credentials.response.clientDataJSON,
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
    rawId: credentials.rawId,
    response: {
      authenticatorData: credentials.response.authenticatorData,
      clientDataJSON: credentials.response.clientDataJSON,
      signature: credentials.response.signature,
      userHandle: credentials.response.userHandle,
    },
    type: credentials.type,
    authenticatorAttachment: credentials.authenticatorAttachment,
    clientExtensionResults: {},
  }
}


function formatLoginOptions(options) {
  return {
    rpId: options.rpId,
    challenge: base64urlToUint8Array(options.challenge),
    timeout: options.timeout,
    allowCredentials: [{
      type: options.allowCredentials[0].type,
      id: base64urlToUint8Array(options.allowCredentials[0].id),
    }],
    userVerification: options.userVerification,
  }
}


registerForm.addEventListener('submit', register);
loginForm.addEventListener('submit', login);