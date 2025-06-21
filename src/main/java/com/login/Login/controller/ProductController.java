package com.login.Login.controller;

import com.login.Login.domain.product.Product;
import com.login.Login.domain.product.ProductRequestDTO;
import com.login.Login.domain.product.ProductResponseDTO;
import com.login.Login.repositories.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/products")
public class ProductController {

    @Autowired
    private ProductRepository productRepository;

    @PostMapping("/new")
    public ProductResponseDTO newProduct(@RequestBody ProductRequestDTO productRequestDTO) {
        Product product = productRepository.save(new Product(
                null,
                productRequestDTO.name(),
                productRequestDTO.price()
        ));
        return new ProductResponseDTO(
                product.getId(),
                product.getName(),
                product.getPrice()
        );
    }

    @GetMapping("/get")
    public List<ProductResponseDTO> getProducts() {
        List<Product> products = productRepository.findAll();
        return products.stream()
                .map(e -> new ProductResponseDTO(
                        e.getId(),
                        e.getName(),
                        e.getPrice()
                ))
                .collect(Collectors.toList());
    }
}
