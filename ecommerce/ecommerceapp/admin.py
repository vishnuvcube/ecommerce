from django.contrib import admin

from ecommerceapp.models import contcat, product,Orders,OrderUpdate

admin.site.register(contcat)
admin.site.register(product)
admin.site.register(Orders)
admin.site.register(OrderUpdate)

# Register your models here.
