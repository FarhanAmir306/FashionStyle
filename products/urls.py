from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CategoryView,ProductView,BestSellerView,AcceptProductView,BuyProduct,ProductDetailsAPIView,get_products_by_category

router = DefaultRouter()
router.register('categories', CategoryView, basename='category')
router.register('all_product', ProductView, basename='products')
router.register('bestseller', BestSellerView, basename='bestseller')
router.register('accept_product', AcceptProductView, basename='accept_product')

urlpatterns = [
    path('', include(router.urls)),
    path('buy/<int:product_id>/', BuyProduct.as_view(), name='buy'),
    path('details/<int:pk>/', ProductDetailsAPIView.as_view(), name='product_details'),
    path('category/<str:category_slug>/products/', get_products_by_category, name='get_products_by_category'),
]