from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
import requests
from rest_framework.response import Response
from rest_framework.decorators import api_view
from drf_social_oauth2.views import ConvertTokenView
from rest_framework_simplejwt.tokens import AccessToken
from oauth2_provider.models import AccessToken as OAuth2AccessToken
from rest_framework.views import APIView
from django.contrib.auth import logout as auth_logout
from rest_framework_simplejwt.tokens import RefreshToken
# Create your views here.
from oauthlib.common import UNICODE_ASCII_CHARACTER_SET
from random import SystemRandom


def index(request):
    return HttpResponse("Hello, world. You're at the mainApp index.")

def about(request):
    return HttpResponse("Hello, world. You're at the mainApp about.")

def login(request):
    return HttpResponse("Hello, world. You're at the mainApp login.")


def google_logout(request):
    # Revoke the access token
    access_token = request.session.get('access_token')  # Retrieve the token from session or other storage
    print(access_token)
    if access_token:
        revoke_url = f'https://oauth2.googleapis.com/revoke?token={access_token}'
        requests.post(revoke_url)
    
    # Clear the session and log out the user
    auth_logout(request)
    return redirect('/')


def _generate_state_session_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
        # This is how it's implemented in the official SDK
        rand = SystemRandom()
        state = "".join(rand.choice(chars) for _ in range(length))
        return state


@api_view(['GET'])
def google_login(request):
    #redirect_uri = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI
    #return redirect(f'https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY}&redirect_uri={redirect_uri}&scope=openid%20email%20profile')
    redirect_uri = 'http://localhost:8000/auth/complete/google/'
    client_id = settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY
    state = _generate_state_session_token()
    request.session['oauth2_state'] = state
    print("STATE: ", state)
    scope = 'openid email profile'
    auth_url = (
        f'https://accounts.google.com/o/oauth2/v2/auth'
        f'?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}'
    )
    return redirect(auth_url)

from attrs import define
import jwt

def decode_jwt(token):
    id_token = token
    decoded_token = jwt.decode(jwt=id_token, options={'verify_signature': False})
    return decoded_token

@api_view(['GET'])
def google_callback(request):
    code = request.GET.get('code')
    state = request.GET.get('state')
    print('CODE: ', code)
    print('STATE FROM REQUEST: ', state)
    if state == request.session['oauth2_state']:
        print("STATE IS CORRECT")
    token_url = 'https://oauth2.googleapis.com/token'
    payload = {
        'code': code,
        'client_id': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
        'client_secret': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
        'redirect_uri': 'http://localhost:8000/auth/complete/google/',
        'grant_type': 'authorization_code',
        'access_type': 'offline',
        'prompt': 'consent'
    }
    response = requests.post(token_url, data=payload)
    tokens = response.json()
    print(tokens)
    access_token = tokens.get('access_token')
    id_token = tokens.get('id_token')
    #decode_jwt(id_token)

    if not access_token:
        return redirect('/')

    user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    user_info_response = requests.get(user_info_url, headers=headers)
    user_info = user_info_response.json()

    # Extract user information
    email = user_info.get('email')
    name = user_info.get('name')

    user, created = User.objects.get_or_create(email=email, defaults={'username': email, 'first_name': name})

    # Authenticate and log in the user
    user = authenticate(request, username=email)  # Use email as the username for authentication
    if user is not None:
        login(request, user)

    toks = generate_jwt(access_token)
    print(toks)
    #return redirect('/')
    result = {
        'jwt_token': toks,
        'user_info': decode_jwt(id_token)
    }
    return Response(result)
    #redirect('/')

def generate_jwt(oauth2_token_string):
    user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
    headers = {
        'Authorization': f'Bearer {oauth2_token_string}'
    }
    user_info_response = requests.get(user_info_url, headers=headers)
    
    if user_info_response.status_code != 200:
        raise ValueError("Invalid OAuth2 token or unable to retrieve user information")
    
    user_info = user_info_response.json()
    
    # Extract user information
    email = user_info.get('email')
    name = user_info.get('name')
    
    if not email:
        raise ValueError("User email is missing from OAuth2 token information")

    # Create or retrieve the user in Django
    user, created = User.objects.get_or_create(email=email, defaults={'username': email, 'first_name': name})
    
    # Generate JWT for this user
    #token = AccessToken.for_user(user)
    refresh = RefreshToken.for_user(user)
    access = refresh.access_token
    # Return the JWT token as a string
    #return str(token)
    return {
        'access': str(access),
        'refresh': str(refresh)
    }


class MyView(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        print("TEST")
        print(data)
        response_data = generate_jwt(data['oauth2_token'])
        print("TEST")
        print(response_data)
        return Response({"jwt_token": response_data})

def test(request):
    return HttpResponse("Hello, world. You're at the mainApp test.")







'''
    if access_token:
        user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info = user_info_response.json()

        # Handle user info and login logic
        email = user_info.get('email')
        name = user_info.get('name')

        # Create or get the user
        user, created = User.objects.get_or_create(username=email, defaults={'email': email, 'first_name': name})

        if created:
            user.set_unusable_password()
            user.save()

        # Log in the user
        login(request, user)
        return redirect('/')
    else:
        return HttpResponse('Error: No access token received', status=400)
    '''

'''
    code = request.GET.get('code')
    token_url = 'https://oauth2.googleapis.com/token'
    payload = {
        'code': code,
        'client_id': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
        'client_secret': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
        'redirect_uri': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    response = requests.post(token_url, data=payload)
    tokens = response.json()
    access_token = tokens.get('access_token')
    print(access_token)
    # Handle tokens and authenticate the user
    return redirect('login/')

@api_view(['POST'])
def convert_token_to_jwt(request):
    # Call the original convert token view
    convert_token_view = ConvertTokenView.as_view()
    response = convert_token_view(request._request)

    if response.status_code == 200:
        # Get the user from the OAuth2 token
        user = request.user
        # Generate a JWT token
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

    return response
'''
