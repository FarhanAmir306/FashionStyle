

# views.py
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate, login, logout
from .serializers import UserSerializer, LoginSerializer

# class RegisterView(APIView):
#     serializer_class = UserSerializer
#     def post(self, request):
#         serializer = UserSerializer(data=request.data)
#         if serializer.is_valid():
#             serializer.save()

#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

class RegisterView(APIView):
    serializer_class = UserSerializer

    def post(self, request):
        serializer = UserSerializer(data=request.data)
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
        print("request",request.data)
        serializer = LoginSerializer(data=request.data)
        print(serializer)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            print(username)
            print(password)
            user = authenticate(request,username=username, password=password)
            print(user)
            
            if user:
                login(request, user)
                return Response({'message': 'Login successful'})
            else:
                return Response({'error': 'Invalid credentials'},status=status.HTTP_401_UNAUTHORIZED)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    
    def get(self, request):
        logout(request)
        return Response({'message': 'Successfully logged out'})
