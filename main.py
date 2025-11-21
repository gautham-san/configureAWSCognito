# main.py
import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import boto3

import hmac
import hashlib
import base64

import urllib.parse
from io import BytesIO
import qrcode
from fastapi.responses import StreamingResponse


from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# Client setup

COGNITO_REGION = os.getenv("COGNITO_REGION", "us-east-1")
USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")

cognito = boto3.client("cognito-idp", region_name=COGNITO_REGION)

# MODELS

class UserCreate(BaseModel):
    name: str
    password: str
    email: str


class UserLogin(BaseModel):
    username: str
    password: str

class MfaSetupStart(BaseModel):
    session: str        # session returned from login when ChallengeName == "MFA_SETUP"

class MfaVerifySetup(BaseModel):
    session: str
    code: str           # 6-digit code from authenticator app

class MfaVerifyLogin(BaseModel):
    session: str
    username: str
    code: str

# Create User

@app.post("/users/create")
def create_user(data: UserCreate):
    try:
        secret_hash = calculate_secret_hash(data.email)

        resp = cognito.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,  # uncomment if using client secret
            Username=data.email,
            Password=data.password,
            UserAttributes=[
                {"Name": "email", "Value": data.email},
                {"Name": "name", "Value": data.name},
            ],
        )

        cognito.admin_confirm_sign_up(
                UserPoolId=USER_POOL_ID,
                Username=data.email,
                )


        return {
            "user_sub": resp["UserSub"],
            "status": "SIGNUP_AND_CONFIRMED",
        }

    except cognito.exceptions.UsernameExistsException:
        raise HTTPException(status_code=400, detail="Username already exists")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
def calculate_secret_hash(username: str) -> str:
    message = username + CLIENT_ID
    dig = hmac.new(
        COGNITO_CLIENT_SECRET.encode("utf-8"),
        msg=message.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    return base64.b64encode(dig).decode()

# Get User

class AccessTokenInput(BaseModel):
    access_token: str

@app.post("/users/me")
def get_user(data: AccessTokenInput):
    try:
        resp = cognito.get_user(AccessToken=data.access_token)
        return {"username": resp["Username"], "attributes": resp["UserAttributes"]}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Auth

@app.post("/auth/login")
def auth_user(data: UserLogin):
    try:
        # Here we assume username == email; you’ll POST email as "username"
        secret_hash = calculate_secret_hash(data.username)

        resp = cognito.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": data.username,
                "PASSWORD": data.password,
                "SECRET_HASH": secret_hash,
            },
        )

        challenge = resp.get("ChallengeName")

        if not challenge:
            # login success, tokens returned
            return {
                "status": "AUTH_SUCCESS",
                "id_token": resp["AuthenticationResult"]["IdToken"],
                "access_token": resp["AuthenticationResult"]["AccessToken"],
                "refresh_token": resp["AuthenticationResult"]["RefreshToken"],
            }

        # 1) User must set up MFA first time
        if challenge == "MFA_SETUP":
            return {
                "status": "MFA_SETUP_REQUIRED",
                "session": resp["Session"],
            }

        # 2) User already has TOTP; Cognito wants MFA code
        if challenge == "SOFTWARE_TOKEN_MFA":
            return {
                "status": "MFA_REQUIRED",
                "session": resp["Session"],
            }

        # other challenge types (NEW_PASSWORD_REQUIRED, etc.)
        return {
            "status": "CHALLENGE",
            "challenge_name": challenge,
            "session": resp["Session"],
        }

    except cognito.exceptions.NotAuthorizedException as e:
        # For debugging, show Cognito's exact message.
        # Once stable, you can swap to a generic "Invalid username or password".
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Setup MFA

import urllib.parse

@app.post("/mfa/setup/start")
def mfa_setup_start(data: MfaSetupStart):
    try:
        resp = cognito.associate_software_token(
            Session=data.session
        )
        secret = resp["SecretCode"]
        new_session = resp["Session"]

        # Build otpauth URL (scan this in Google Authenticator / Authy)
        issuer = "MyApp"
        label = urllib.parse.quote(f"{issuer}:{'cognito-user'}")
        otpauth_url = (
            f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"
            "&algorithm=SHA1&digits=6&period=30"
        )

        # Generate QR code image for otpauth_url
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(otpauth_url)
        qr.make(fit=True)
        img = qr.make_image()

        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        # Base64 encode the image so you can just paste into <img src="...">
        img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        data_url = f"data:image/png;base64,{img_b64}"

        return {
            "status": "MFA_SETUP_TOKEN_CREATED",
            "secret": secret,
            "session": new_session,
            "otpauth_url": otpauth_url,
            "qr_image_data_url": data_url,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# Verify MFA

@app.post("/mfa/setup/verify")
def mfa_setup_verify(data: MfaVerifySetup):
    try:
        resp = cognito.verify_software_token(
            Session=data.session,
            UserCode=data.code,
            FriendlyDeviceName="AuthenticatorApp",
        )
        status = resp.get("Status")
        if status != "SUCCESS":
            raise HTTPException(status_code=400, detail=f"MFA verify failed: {status}")

        # At this point TOTP is associated with user.
        # You may now call SetUserMFAPreference (needs access token or admin call).

        return {"status": "MFA_SETUP_COMPLETE"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

def set_totp_as_preferred(access_token: str):
    cognito.set_user_mfa_preference(
        SoftwareTokenMfaSettings={
            "Enabled": True,
            "PreferredMfa": True,
        },
        AccessToken=access_token,
    )

# Verify MFA during login

@app.post("/auth/login/verify-mfa")
def auth_verify_mfa(data: MfaVerifyLogin):
    try:

        secret_hash = calculate_secret_hash(data.username)

        resp = cognito.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=data.session,
            ChallengeResponses={
                "USERNAME": data.username,
                "SOFTWARE_TOKEN_MFA_CODE": data.code,
                "SECRET_HASH": secret_hash,
            },
        )

        if "AuthenticationResult" not in resp:
            raise HTTPException(status_code=400, detail="MFA verification failed")

        auth_result = resp["AuthenticationResult"]

        return {
            "status": "AUTH_SUCCESS",
            "id_token": auth_result["IdToken"],
            "access_token": auth_result["AccessToken"],
            "refresh_token": auth_result.get("RefreshToken"),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
class EmailSendCode(BaseModel):
    access_token: str

class EmailVerify(BaseModel):
    access_token: str
    code: str


@app.post("/admin/email/force_verify")    
def admin_force_verify_email(username: str):
    cognito.admin_update_user_attributes(
        UserPoolId=USER_POOL_ID,
        Username=username,  # in your case, the email itself
        UserAttributes=[
            {"Name": "email_verified", "Value": "true"},
        ],
    )


@app.post("/email/verify")
def verify_email(data: EmailVerify):
    try:
        cognito.verify_user_attribute(
            AccessToken=data.access_token,
            AttributeName="email",
            Code=data.code,
        )
        return {"status": "EMAIL_VERIFIED"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/email/send-code")
def send_email_verification(data: EmailSendCode):
    try:
        resp = cognito.get_user_attribute_verification_code(
            AccessToken=data.access_token,
            AttributeName="email",
        )
        # resp contains CodeDeliveryDetails if you need it
        return {
            "status": "CODE_SENT",
            "delivery": resp.get("CodeDeliveryDetails", {}),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
