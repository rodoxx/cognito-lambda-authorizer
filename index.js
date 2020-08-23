const jwt = require('jsonwebtoken')
const AWS = require('aws-sdk');
const cognito = new AWS.CognitoIdentityServiceProvider({ region: 'eu-west-2'});

const validateAccess = async (event) => {
  return await new Promise ((resolve, reject) => {
    const token = event.authorizationToken;
    const methodArn = event.methodArn;
    const { sub } = jwt.decode(token)

    cognito.getUser({ AccessToken: token }, (err, obj) => {
      if (!err) {
        resolve(generateAuthResponse(`user|${sub}`, 'Allow', methodArn))
      } else {
        resolve(generateAuthResponse(`user|${sub}`, 'Deny', methodArn))
      }
    })
  })
}

function generateAuthResponse(principalId, effect, methodArn) {
  const policyDocument = generatePolicyDocument(effect, methodArn);

  return { 
    principalId, 
    policyDocument 
  }
}

function generatePolicyDocument(effect, methodArn) {
  if (!effect || !methodArn) return null;

  const policyDocument = {
    Version: '2012-10-17',
    Statement: [{
      Action: 'execute-api:Invoke',
      Effect: effect,
      Resource: methodArn
    }]
  }

  return policyDocument;
}

const main = async (event) => {
  return validateAccess(event);
}

exports.handler = main