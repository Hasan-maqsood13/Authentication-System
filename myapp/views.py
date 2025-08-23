from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
import re
from django.shortcuts import render, redirect
from .models import Account  
import random
from django.contrib.auth.hashers import check_password
from django.http import JsonResponse
from django.urls import reverse
import json, re
from django.views.decorators.csrf import csrf_exempt





#Create your views here.
def generate_verification_code(length=8):
    """Generate a random 4-digit numeric code"""
    return str(random.randint(1000, 9999))

@csrf_exempt  # Agar CSRF token sahi pass ho raha to zarurat nahi
def signup(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        errors = {}

        if not name:
            errors['name'] = "Name is required."
        elif not re.match(r'^[A-Za-z ]+$', name):
            errors['name'] = "Name can only contain letters and spaces."

        if not email:
            errors['email'] = "Email is required."
        elif Account.objects.filter(email=email).exists():
            errors['email'] = "This email is already registered."

        if not password:
            errors['password'] = "Password is required."
        else:
            if len(password) < 8:
                errors['password'] = "Password must be at least 8 characters long."
            elif not re.search(r'[A-Z]', password):
                errors['password'] = "Password must contain at least one uppercase letter."
            elif not re.search(r'[a-z]', password):
                errors['password'] = "Password must contain at least one lowercase letter."
            elif not re.search(r'\d', password):
                errors['password'] = "Password must contain at least one digit."
            elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                errors['password'] = "Password must contain at least one special character."

        if errors:
            # AJAX request ke liye JSON return karenge
            return JsonResponse({'success': False, 'errors': errors})

        verification_code = generate_verification_code()

        user = Account.objects.create(
            name=name,
            email=email,
            password=make_password(password),
            verification_code=verification_code
        )

        send_mail(
            'Verify Your Email',
            f'Hello {user.name},\n\nThank you for registering!\nYour verification code is: {verification_code}',
            'your_email@gmail.com',  # apna sender email yahan daalo
            [user.email],
            fail_silently=False,
        )

        # Success me JSON bhejo, email ko frontend redirect ke liye bhej rahe hain
        return JsonResponse({'success': True, 'email': user.email})

    # Agar GET request aayi ho to HTML form render karo
    return render(request, 'signup.html')

def verify_code(request):
    error = ''
    email = request.GET.get('email')

    if not email:
        return redirect('signup')

    user = Account.objects.filter(email=email).first()
    if not user:
        return redirect('signup')

    # If resend requested
    if request.method == 'POST' and request.POST.get('action') == 'resend':
        # Generate and send new code
        new_code = generate_verification_code()
        user.verification_code = new_code
        user.save()
        send_mail(
            'Verify Your Email - New Code',
            f'Your new verification code is: {new_code}',
            'your_email@gmail.com',
            [user.email],
            fail_silently=False,
        )
        return JsonResponse({'success': True})

    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if user.verification_code == code:
            user.is_verified = True
            user.verification_code = ''
            user.save()
            return redirect('login')
        else:
            error = 'Invalid verification code.'

    return render(request, 'verify.html', {'error': error, 'email': email})



def login_view(request):
    error = ''
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        try:
            user = Account.objects.get(email=email)

            if not user.is_verified:
                error = 'Please verify your email before logging in.'
            if not check_password(password, user.password):
                error = 'Incorrect password.'
            else:
                # ✅ Save user info in session
                request.session['user_id'] = user.id
                request.session['locked'] = False

                # ✅ Role-based redirect
                if user.role == 'admin':
                    return redirect('admin_dashboard')
                else:
                    return redirect('customer_dashboard')

        except Account.DoesNotExist:
            error = 'No account found with this email.'

    return render(request, 'login.html', {'error': error})

def forgot_password_email(request):
    error = ''
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        try:
            user = Account.objects.get(email=email)
            code = generate_verification_code()
            user.verification_code = code
            user.save()
            send_mail(
                'Password Reset Code',
                f'Your password reset code is: {code}',
                'your_email@gmail.com',
                [user.email],
                fail_silently=False,
            )
            return redirect(f'{reverse("verify_reset_code")}?email={email}')
        except Account.DoesNotExist:
            error = 'No account found with this email.'
    return render(request, 'forgot_password_email.html', {'error': error})

def verify_reset_code(request):
    error = ''
    email = request.GET.get('email')
    if not email:
        return redirect('login')
    user = Account.objects.filter(email=email).first()
    if not user:
        return redirect('login')

    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if code == user.verification_code:
            # Clear code to prevent reuse
            user.verification_code = ''
            user.save()
            return redirect(f'{reverse("reset_password")}?email={email}')
        else:
            error = 'Invalid code.'
    return render(request, 'verify_reset_code.html', {'error': error, 'email': email})


def reset_password(request):
    error = ''
    email = request.GET.get('email')
    if not email:
        return redirect('login')
    user = Account.objects.filter(email=email).first()
    if not user:
        return redirect('login')

    if request.method == 'POST':
        new_pass = request.POST.get('new_password', '')
        confirm = request.POST.get('confirm_password', '')
        if new_pass != confirm:
            error = 'Passwords do not match.'
        elif len(new_pass) < 8 or not re.search(r'[A-Z]', new_pass) or not re.search(r'[a-z]', new_pass) or not re.search(r'\d', new_pass) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_pass):
            error = 'Password does not meet requirements.'
        else:
            user.password = make_password(new_pass)
            user.save()
            return redirect('login')
    return render(request, 'reset_password.html', {'error': error, 'email': email})




def admin_dashboard(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    if request.session.get('locked', False):
        return redirect('lock_screen')

    user = Account.objects.get(id=user_id)
    if user.role != 'admin':
        return redirect('customer_dashboard')  # Not allowed

    return render(request, 'admin_dashboard.html', {'user': user})



def customer_dashboard(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    if request.session.get('locked', False):
        return redirect('lock_screen')

    user = Account.objects.get(id=user_id)
    if user.role != 'customer':
        return redirect('admin_dashboard')  # Not allowed

    return render(request, 'customer_dashboard.html', {'user': user})


def logout_view(request):
    request.session.flush()  # ❌ Clear session
    return redirect('login')

def lock_screen(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    # Lock the session
    request.session['locked'] = True

    return render(request, 'lockscreen.html')


def unlock_screen(request):
    error = ''
    user_id = request.session.get('user_id')

    if not user_id:
        return redirect('login')

    try:
        user = Account.objects.get(id=user_id)
    except Account.DoesNotExist:
        return redirect('login')

    if request.method == 'POST':
        password = request.POST.get('password')

        if check_password(password, user.password):
            request.session['locked'] = False  # ✅ Unlock session

            # ✅ Role-based redirect after unlock
            if user.role == 'admin':
                return redirect('admin_dashboard')
            else:
                return redirect('customer_dashboard')
        else:
            error = "Incorrect password."

    return render(request, 'lockscreen.html', {'error': error})


