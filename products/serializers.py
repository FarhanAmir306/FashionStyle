# serializers.py
from rest_framework import serializers
from .models import Category,Product,BestSeller,Accept_Product

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields ='__all__'


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model=Product
        fields='__all__'


class BestSellerSerilizer(serializers.ModelSerializer):
    class Meta:
        model=BestSeller
        fields='__all__'

class AcceptProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Accept_Product
        fields = ['user', 'products']
        



        