from django.urls import path
from . import views

urlpatterns = [
    path('', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
    path('verify/', views.verify_code, name='verify'),
    path('logout/', views.logout_view, name='logout'),
    path('lock/', views.lock_screen, name='lock_screen'),
    path('unlock/', views.unlock_screen, name='unlock_screen'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('customer-dashboard/', views.customer_dashboard, name='customer_dashboard'),
    path('forgot-password/', views.forgot_password_email, name='forgot_password_email'),
    path('verify-reset/', views.verify_reset_code, name='verify_reset_code'),
    path('reset-password/', views.reset_password, name='reset_password'),
]
