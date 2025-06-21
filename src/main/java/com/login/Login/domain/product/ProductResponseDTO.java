package com.login.Login.domain.product;

import java.math.BigDecimal;
import java.util.UUID;

public record ProductResponseDTO(UUID id, String name, BigDecimal price) {
}
