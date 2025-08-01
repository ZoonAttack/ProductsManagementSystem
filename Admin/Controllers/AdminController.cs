using Admin.Models;
using Microsoft.AspNetCore.Mvc;
using Shared.DTOs;
using ProductsManagement.Models;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc.Rendering;
using Shared.Utility;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace Admin.Controllers
{
    public class AdminController : Controller
    {
        private readonly ILogger<AdminController> _logger;
        private readonly ApiCalls _apiCall;
        public AdminController(ILogger<AdminController> logger, ApiCalls apiCall)
        {
            _logger = logger;
            _apiCall = apiCall;
        }

        #region Authentication
        [HttpGet]
        public IActionResult Login()
        {
            return View();

        }
        [HttpPost]
        public async Task<IActionResult> Login(LoginUserDto loginDto)
        {
            ApiResponse<Tuple<string, string>> result = await _apiCall.LoginAsync(loginDto);
            var data = result.Data;
            if(result.Success == false || data == null)
            {
                ViewData["ErrorMessage"] = result.Message ?? "Login failed.";
                return View(loginDto);
            }
            if (data.Item2.Equals("admin"))
            {
                // Save token in session if needed
                HttpContext.Session.SetString("token", data.Item1);

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, loginDto.Email),
                    new Claim(ClaimTypes.Role, data.Item2),
                    new Claim("AccessToken", data.Item1) // optional if you want to use it later
                };

                var identity = new ClaimsIdentity(claims, "MyCookieAuth");
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync("MyCookieAuth", principal);

                return RedirectToAction("Dashboard", "Admin");
            }
            ViewData["ErrorMessage"] = data.Item2 ?? "Invalid login.";
            return View(loginDto);
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _apiCall.LogoutAsync();

            // Then sign out locally
            await HttpContext.SignOutAsync("MyCookieAuth");
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Admin");
        }

        #endregion

        #region Products
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> UpdateProduct(int id)
        {

            var result = await _apiCall.GetProductAsync(id);
            var categoryResult = await _apiCall.GetCategoryAsync(result.Data.Category);
            int categoryId = categoryResult.Data!.CategoryId;
            if (!result.Success) return NotFound(result.Message);
            var dto = new CreateProductDto
            {
                Name = result.Data.Name,
                Description = result.Data.Description,
                Price = result.Data.Price,
                Status = result.Data.Status.ToString(),
                ImageUrl = result.Data.ImageUrl,
                CategoryId = categoryId
            };
            
            var categories = await _apiCall.GetCategoriesAsync();

            CreateProductViewModel vm = new CreateProductViewModel
            {
                ProductId = id,
                Product = dto,
                Categories = categories.Data!,
                productStatuses = Enum.GetValues(typeof(ProductStatus)).Cast<ProductStatus>().ToList()
            };
            return View("UpdateProduct", vm);
        }
        [HttpPost]
        [Authorize]
        public async Task<IActionResult> UpdateProduct(int id, CreateProductViewModel dto)
        {
            var result = await _apiCall.UpdateProductAsync(dto.Product, id);
            if (!result.Success)
            {
                ViewBag.ProductId = id;
                ViewBag.Error = result.Message;
                return View(dto);
            }

            TempData["Message"] = "Product updated successfully";
            return RedirectToAction("Dashboard");
        }

        [HttpGet]
        [Authorize]
        public IActionResult CreateProduct()
        {
            var categories = _apiCall.GetCategoriesAsync().Result.Data;
            CreateProductViewModel vm = new CreateProductViewModel
            {
                Product = new CreateProductDto(),
                Categories = categories!,
                productStatuses = Enum.GetValues(typeof(ProductStatus)).Cast<ProductStatus>().ToList()
            };
            return View(vm);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> CreateProduct(CreateProductViewModel dto)
        {
            var result = await _apiCall.CreateProductAsync(dto.Product);
            if (!result.Success)
            {
                ViewBag.Error = result.Message;
                return View(dto);
            }

            TempData["Message"] = "Product created successfully";
            return RedirectToAction("Dashboard");
        }
        [HttpPost]
        [Authorize]
        public async Task<IActionResult> DeleteProduct(int Id)
        {
            var result = await _apiCall.DeleteProductAsync(Id);
            if (result.Success)
            {
                return RedirectToAction("Dashboard");
            }
            else
            {
                ViewData["ErrorMessage"] = result.Message ?? "Failed to delete product.Has ongoing items";
                return RedirectToAction("Dashboard");
            }
        }
        #endregion

        #region Orders
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> UpdateOrder(int id)
        {

            var result = await _apiCall.GetOrderAsync(id);
            if (!result.Success) return NotFound(result.Message);
            var dto = new CreateOrderDto
            {
                OrderItems = result.Data.OrderItems,
                ShippingAddress = result.Data.ShippingAddress,
                PaymentMethod = result.Data.Payment.PaymentMethod,
                Status = result.Data.Status.ToString()
            };

            CreateOrderViewModel vm = new CreateOrderViewModel
            {
                OrderId = id,
                Order = dto,
                OrderStatuses = Enum.GetValues(typeof(OrderStatus)).Cast<OrderStatus>().ToList(),
                PaymentMethods = Enum.GetValues(typeof(PaymentMethods)).Cast<PaymentMethods>().ToList(),
                Products = _apiCall.GetProductsAsync().Result.Data ?? new List<ProductSummaryDto>()
            };
            return View("UpdateOrder", vm);
        }

        [HttpPost]
        public async Task<IActionResult> UpdateOrder(int id, CreateOrderViewModel dto)
        {
            var result = await _apiCall.UpdateOrderAsync(dto.Order, id);
            if (!result.Success)
            {
                ViewBag.OrderId = id;
                ViewBag.Error = result.Message;
                return View(dto);
            }

            TempData["Message"] = "Order updated successfully";
            return RedirectToAction("Dashboard");
        }

        [HttpGet]
        [Authorize]
        public IActionResult CreateOrder()
        {
            CreateOrderViewModel vm = new CreateOrderViewModel
            {
                Order = new CreateOrderDto(),
                OrderStatuses = Enum.GetValues(typeof(OrderStatus)).Cast<OrderStatus>().ToList(),
                Products = _apiCall.GetProductsAsync().Result.Data ?? new List<ProductSummaryDto>(),
                PaymentMethods = Enum.GetValues(typeof(PaymentMethods)).Cast<PaymentMethods>().ToList()
            };
            
            return View(vm);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> CreateOrder(CreateOrderViewModel dto)
        {
            var result = await _apiCall.CreateOrderAsync(dto.Order);
            if (!result.Success)
            {
                ViewBag.Error = result.Message;
                return View(dto);
            }

            TempData["Message"] = "Order created";
            return RedirectToAction("Dashboard");
        }


        [HttpPost]
        [Authorize]
        public async Task<IActionResult> DeleteOrder(int id)
        {
            var result = await _apiCall.DeleteOrderAsync(id);
            if (result.Success)
            {
                return RedirectToAction("Dashboard");
            }
            else
            {
                ViewData["ErrorMessage"] = result.Message ?? "Failed to delete order.";
                return RedirectToAction("Dashboard");
            }
        }


        [HttpGet]
        [Authorize]
        public async Task<IActionResult> DownloadInvoice(int id)
        {
            var result = await _apiCall.GetInvoiceAsync(id);
            if(!result.Success || result.Data == null)
            {
                TempData["Error"] = result.Message ?? "Failed to retrieve invoice.";
                return RedirectToAction("Dashboard");
            }
            var file = result.Data;
            return File(file.Content, file.ContentType, file.FileName);
        }

        #endregion


        #region Categories

        [HttpGet]
        [Authorize]
        public IActionResult CreateCategory()
        {
            return View();
        }
        [HttpPost]
        [Authorize]

        public async Task<IActionResult> CreateCategory(CreateCategoryDto dto)
        {
            var result = await _apiCall.CreateCategoryAsync(dto);
            if (!result.Success)
            {
                ViewBag.Error = result.Message;
                return View(dto);
            }
            TempData["Message"] = "Category created successfully";
            return RedirectToAction("Dashboard");
        }
        #endregion
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Dashboard()
        {
            var products = await _apiCall.GetProductsAsync();
            var productsData = products.Data;
            var orders = await _apiCall.GetOrdersAsync();
            var ordersData = orders.Data;
            AdminDashboardViewModel model = new AdminDashboardViewModel()
            {
                Products = productsData ?? new List<ProductSummaryDto>(),
                Orders = ordersData ?? new List<OrderSummaryDto>()
            };

            return View(model);
        }
        [HttpGet]
        public async Task<IActionResult> GetDetailsPartial(int id, string type)
        {
            if (type == "product")
            {
                var product = await _apiCall.GetProductAsync(id);
                var productData = product.Data;
                return PartialView("_ProductDetailPartial", productData);
            }
            else if (type == "order")
            {
                var order = await _apiCall.GetOrderAsync(id);
                var orderData = order.Data;
                return PartialView("_OrderDetailPartial", orderData);
            }

            return BadRequest("Unknown type.");
        }

    }
}
