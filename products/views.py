from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from rest_framework import viewsets
from .models import Category,Product,BestSeller,Accept_Product
from .serializers import CategorySerializer,ProductSerializer,BestSellerSerilizer,AcceptProductSerializer
# Create your views here.



class CategoryView(viewsets.ModelViewSet):
    queryset=Category.objects.all()
    serializer_class=CategorySerializer


class ProductView(viewsets.ModelViewSet):
    queryset=Product.objects.all()
    serializer_class=ProductSerializer

class BestSellerView(viewsets.ModelViewSet):
    queryset=BestSeller.objects.all()
    serializer_class=BestSellerSerilizer


class AcceptProductView(viewsets.ModelViewSet):
    queryset=Accept_Product.objects.all()
    serializer_class=AcceptProductSerializer 




from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404



class BuyProduct(APIView):
    
    def get(self, request, product_id):
        
        product = get_object_or_404(Product, pk=product_id)
        user = request.user
        print(user)
        # Assuming you have authentication set up

        # Create an entry in Accept_Product for the purchased product
        serializer = AcceptProductSerializer(data={'user': user.id, 'products': product.id}) 
        if serializer.is_valid():
            serializer.save()

            # Update product quantity (subtract 1)
            product.quantity -= 1
            product.save()

            return Response({'message': 'Purchase successful'}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class ProductDetailsAPIView(APIView):
    def get(self, request, pk):
        try:
            # Retrieve the product by primary key (pk)
            product = Product.objects.get(pk=pk)
            
            # Serialize the product data
            serializer = ProductSerializer(product)
            
            # Return the serialized data as a response
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Product.DoesNotExist:
            # If the product with the given pk does not exist, return a 404 response
            return Response({"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND)
        
from rest_framework.decorators import api_view
from django.http import JsonResponse
@api_view(['GET'])
def get_products_by_category(request, category_slug):
    try:
        category = Category.objects.get(slug=category_slug)
       
        products = Product.objects.filter(category=category)
       
        serializer = ProductSerializer(products, many=True)
        print(serializer)
        return Response(serializer.data)
    except Category.DoesNotExist:
        return JsonResponse({'error': 'Category not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
