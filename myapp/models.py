from django.db import models
from django.utils import timezone



class Account(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)  
    is_verified = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=8, blank=True, null=True)
    date_joined = models.DateTimeField(default=timezone.now)

    
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('customer', 'Customer'), 
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='customer')

    def __str__(self):
        return f"{self.name}     - {self.email} - {self.role}" 
