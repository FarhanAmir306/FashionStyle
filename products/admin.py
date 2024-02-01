from django.contrib import admin
from .models import Product,Category,Accept_Product,BestSeller
# Register your models here.
admin.site.register(Product)
admin.site.register(Category)
admin.site.register(Accept_Product)
admin.site.register(BestSeller)
