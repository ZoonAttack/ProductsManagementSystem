﻿using ProductsManagement.Data;
using Shared.DTOs;

namespace ProductsManagement.DTOs.Mappers
{
    public static class ProductDTOsMapper
    {

        public static ProductDetailsDto ToProductDetailsDto(this Product product)
        {
            return new ProductDetailsDto
            {
                Id = product.Id,
                Name = product.Name,
                Description = product.Description,
                Status = product.Status.ToString(),
                Price = product.Price,
                ImageUrl = product.ImageUrl,
                Category = product.Category.Name ?? "Uncategorized"
            };
        }
        public static ProductSummaryDto ToProductSummaryDto(this Product product)
        {
            return new ProductSummaryDto
            {
                ProductId = product.Id,
                Name = product.Name,
                ImageUrl = product.ImageUrl,
                Status = product.Status.ToString(),
                Price = product.Price
            };
        }

    }
}
