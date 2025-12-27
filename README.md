# Integrating AWS Cognito MFA

### 1. Clone this repo

```
git clone https://github.com/gautham-san/configureAWSCognito
```

### 2. Create an environment and install the requirements

```
python3 -m venv myenv && source myenv/bin/activate && pip install -r requirements.txt
```

### 3. Run the app from main.py

```
uvicorn main:app --reload
```

### 4. Open FastAPI docs to test MFA

```
http://localhost:8000/docs
```


### 5. Open these URLS to test the Google Sign in and Sign out

```
http://localhost:8000/auth/logout/browser
http://localhost:8000/auth/login/google
```

