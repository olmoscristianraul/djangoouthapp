from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth import authenticate, login, logout


class RegistrationView(View):
    def get(self, request):
        return render(request, 'auth/register.html')

    def post(self, request):
        context={
            'data':request.POST,
            'has_error':False
        }
        # data=request.POST
        # print(data)

        email=request.POST.get('email')
        username=request.POST.get('username')
        full_name=request.POST.get('name')
        password=request.POST.get('password')
        password2=request.POST.get('password2')

        if len(password)<6:
            messages.add_message(request,messages.ERROR,'El password debe tener almenos de 6 caracteres')
            context['has_error']=True

        if password!=password2:
            messages.add_message(request,messages.ERROR,'El password ingresado no coincide')
            context['has_error']=True

        if not validate_email(email):
            messages.add_message(request,messages.ERROR,'Ingrese un email válido')
            context['has_error']=True
        try:
            if User.objects.get(email=email):
                messages.add_message(request,messages.ERROR,'El email se encuentra en uso')
                context['has_error']=True
        except Exception as identifier:
            pass

        try:
            if User.objects.get(username=username):
                messages.add_message(request,messages.ERROR,'El usuario se encuentra en uso')
                context['has_error']=True
        except Exception as identifier:
            pass


        if context['has_error']:
            return render(request, 'auth/register.html', context, status=400)


        user=User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name=full_name
        user.last_name=full_name
        user.is_active=False
        user.save()

        current_site=get_current_site(request)
        email_subject='Active su usuario'
        message=render_to_string('auth/activate.html',
        {
            'user':user,
            'domain':current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)
        }
        )

        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            to=[email]
        )

        print(message)

        email_message.send()

        # si envia un error de este tipo
        # SMTPAuthenticationError at /register
        # (535, b'5.7.8 Username and Password not accepted. Learn more at\n5.7.8  https://support.google.com/mail/?p=BadCredentials d25sm5710486qka.39 - gsmtp')
        # se resuelve permitiendo acceso a aplicaciones no seguras 
        # https://support.google.com/accounts/answer/6010255?hl=es

        messages.add_message(request,messages.SUCCESS,'El usuario fue creado correctamente')

        return redirect('login')


        # return render(request, 'auth/register.html', context={'data':data})

class LoginView(View):
    def get(self, request):
        return render(request, 'auth/login.html')
    def post(self, request):
        context={
            'data':request.POST,
            'has_error':False
        }

        username=request.POST.get('username')
        password=request.POST.get('password')

        if username=='':
            messages.add_message(request,messages.ERROR,'Usuario es requerido')
            context['has_error']=True
        if password=='':
            messages.add_message(request,messages.ERROR,'Password es requerido')
            context['has_error']=True

        user=authenticate(request,username=username,password=password)
        
        if not user and not context['has_error']:
            messages.add_message(request,messages.ERROR,'Login error')
            context['has_error']=True

        if context['has_error']:
            return render(request, 'auth/login.html', status=401, context=context)
        
        login(request, user)
        return redirect('home')

        return render(request, 'auth/login.html')

class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid=force_text(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
        except Exception as identifier:
            user=None

        if user is not None and generate_token.check_token(user, token):
            user.is_active=True
            user.save()
        
            messages.add_message(request,messages.SUCCESS,'El usuario fue activado correctamente')

            return redirect('login')

        return render(request,'auth/activate_failed.html', status=401)

class HomeView(View):
    def get(self, request):
        return render(request, 'home.html')


class LogoutView(View):
    
    def post(self, request):
        logout(request)
        messages.add_message(request,messages.SUCCESS,'Session cerrada satisfactoriamente')
        return redirect('login')
