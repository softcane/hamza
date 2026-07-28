package ai.hamza.edm;

import ai.hamza.config.HamzaProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Internal admin API, not an Agent→Provider path. It authenticates with its own admin
 * token; proxied Provider Authorization headers remain outside this controller.
 */
@RestController
@RequestMapping("/admin/registries")
public class RegistryAdminController {

    private final RegistryIngestionService ingestion;
    private final HamzaProperties properties;

    public RegistryAdminController(RegistryIngestionService ingestion,
                                   HamzaProperties properties) {
        this.ingestion = ingestion;
        this.properties = properties;
    }

    @PutMapping(path = "/{name}", consumes = {
            "text/csv", "application/csv", MediaType.TEXT_PLAIN_VALUE,
            MediaType.APPLICATION_OCTET_STREAM_VALUE
    })
    public ResponseEntity<RegistryIngestionReceipt> put(
            @PathVariable String name,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            HttpServletRequest request) throws IOException {
        ResponseEntity<RegistryIngestionReceipt> rejected = rejectUnlessAuthorized(authorization);
        if (rejected != null) {
            return rejected;
        }
        RegistryIngestCommand command = RegistryIngestCommand.fromQuery(name, query(request));
        return ResponseEntity.ok(ingestion.ingest(command, request.getInputStream()));
    }

    @GetMapping
    public ResponseEntity<List<RegistryStats>> list(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        ResponseEntity<List<RegistryStats>> rejected = rejectUnlessAuthorized(authorization);
        if (rejected != null) {
            return rejected;
        }
        return ResponseEntity.ok(ingestion.listRegistries());
    }

    @DeleteMapping("/{name}")
    public ResponseEntity<Void> delete(
            @PathVariable String name,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        ResponseEntity<Void> rejected = rejectUnlessAuthorized(authorization);
        if (rejected != null) {
            return rejected;
        }
        ingestion.delete(name);
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(RegistryIngestionException.class)
    public ResponseEntity<Map<String, String>> ingestError(RegistryIngestionException e) {
        HttpStatus status = switch (e.kind()) {
            case PAYLOAD_TOO_LARGE -> HttpStatus.PAYLOAD_TOO_LARGE;
            case DISABLED -> HttpStatus.NOT_FOUND;
            case BAD_REQUEST -> HttpStatus.BAD_REQUEST;
        };
        String code = e.kind() == RegistryIngestionException.Kind.BAD_REQUEST
                ? RegistryIngestCommand.INVALID_REQUEST
                : e.code();
        return ResponseEntity.status(status).body(Map.of("error", code));
    }

    private <T> ResponseEntity<T> rejectUnlessAuthorized(String authorization) {
        String token = properties.edm().adminToken();
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        String prefix = "Bearer ";
        if (authorization == null || !authorization.startsWith(prefix)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        byte[] expected = token.getBytes(StandardCharsets.UTF_8);
        byte[] actual = authorization.substring(prefix.length()).getBytes(StandardCharsets.UTF_8);
        if (!MessageDigest.isEqual(expected, actual)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return null;
    }

    private static Map<String, List<String>> query(HttpServletRequest request) {
        Map<String, List<String>> query = new LinkedHashMap<>();
        request.getParameterMap().forEach((name, values) ->
                query.put(name, values == null ? List.of() : List.copyOf(Arrays.asList(values))));
        return Map.copyOf(query);
    }
}
