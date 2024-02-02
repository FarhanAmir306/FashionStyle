

# views.py
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate, login, logout
from .serializers import RegistrationSerializer, LoginSerializer
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.shortcuts import redirect

class RegisterView(APIView):
    serializer_class = RegistrationSerializer

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Generate a confirmation link (replace this with your actual link)
            # confirm_link = "https://example.com/confirm/{}/".format(user.activation_token)

            # Email subject and body
            email_subject = "Confirm Your Email"
            email_body = render_to_string('register_mail.html')
            email_plain_text = strip_tags(email_body)  # Plain text version of the email

            # Send the email
            send_mail(
                email_subject,
                email_plain_text,
                'farhangfx306@gmail.com',  # Sender's email address
                [user.email],  # Recipient's email address
                html_message=email_body,  # HTML version of the email
            )

            return Response("Check your mail for confirmation", status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LoginView(APIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = LoginSerializer(data = self.request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            user = authenticate(request, username=username, password=password)
            print(user)
            if user:
                token, _ = Token.objects.get_or_create(user=user)
                login(request, user)
                return Response({'token' : token.key, 'user_id' : user.id})
            else:
                return Response({'error' : "Invalid Credential"})
        return Response(serializer.errors)


class LogoutView(APIView):
    def get(self, request):
        if request.user.is_authenticated:
            # Check if the user is authenticated before trying to delete the token
            request.user.auth_token.delete()
            logout(request)
            return Response({'message': 'Logout successful'})
        else:
            return Response({'message': 'User not authenticated'})
