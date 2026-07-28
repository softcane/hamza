package ai.hamza.edm;

import ai.hamza.config.HamzaProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.InputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RegistryAdminControllerTest {

    @Test
    void adminApiIs404WhenTokenUnset() throws Exception {
        RegistryIngestionService service = mock(RegistryIngestionService.class);
        MockMvc mvc = mvc(service, null);

        mvc.perform(put("/admin/registries/customers")
                        .contentType("text/csv")
                        .content("email\n"))
                .andExpect(status().isNotFound());

        verifyNoInteractions(service);
    }

    @Test
    void missingAndWrongBearerTokenAreRejected() throws Exception {
        RegistryIngestionService service = mock(RegistryIngestionService.class);
        MockMvc mvc = mvc(service, "expected-token");

        mvc.perform(put("/admin/registries/customers")
                        .contentType("text/csv")
                        .content("email\n"))
                .andExpect(status().isForbidden());
        mvc.perform(put("/admin/registries/customers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer wrong-token")
                        .contentType("text/csv")
                        .content("email\n"))
                .andExpect(status().isForbidden());

        verifyNoInteractions(service);
    }

    @Test
    void correctBearerTokenAllowsAdminRead() throws Exception {
        RegistryIngestionService service = mock(RegistryIngestionService.class);
        when(service.listRegistries()).thenReturn(List.of());
        MockMvc mvc = mvc(service, "expected-token");

        mvc.perform(get("/admin/registries")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer expected-token"))
                .andExpect(status().isOk());
    }

    @Test
    void completeTypedQueryBecomesOneImmutableIngestCommand() throws Exception {
        RegistryIngestionService service = mock(RegistryIngestionService.class);
        when(service.ingest(any(RegistryIngestCommand.class), any(InputStream.class)))
                .thenReturn(new RegistryIngestionReceipt("customers", "0".repeat(64), 1, 1, 0, 1));
        MockMvc mvc = mvc(service, "expected-token");

        mvc.perform(put("/admin/registries/customers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer expected-token")
                        .queryParam("columns", "email")
                        .queryParam("replacementKinds", "email:EMAIL")
                        .queryParam("recipe", "synthetic-email:1")
                        .queryParam("blockThreshold", "1")
                        .contentType("text/csv")
                        .content("email\nfake101@example-corp.test\n"))
                .andExpect(status().isOk());

        ArgumentCaptor<RegistryIngestCommand> command =
                ArgumentCaptor.forClass(RegistryIngestCommand.class);
        verify(service).ingest(command.capture(), any(InputStream.class));
        assertThat(command.getValue()).satisfies(value -> {
            assertThat(value.registry()).isEqualTo("customers");
            assertThat(value.columns()).containsExactly("email");
            assertThat(value.replacementKinds()).containsEntry("email", ReplacementKind.EMAIL);
            assertThat(value.recipe()).isEqualTo(new RegistryRecipe("synthetic-email", 1));
            assertThat(value.blockThreshold()).isEqualTo(1);
        });
    }

    @Test
    void unknownQueryParameterReturnsTheFixedContentFreeError() throws Exception {
        RegistryIngestionService service = mock(RegistryIngestionService.class);
        MockMvc mvc = mvc(service, "expected-token");

        mvc.perform(put("/admin/registries/customers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer expected-token")
                        .queryParam("columns", "email")
                        .queryParam("surprise", "fake101@example-corp.test")
                        .contentType("text/csv")
                        .content("email\nfake101@example-corp.test\n"))
                .andExpect(status().isBadRequest())
                .andExpect(content().json("""
                        {"error":"invalid-registry-ingest-request"}
                        """));

        verifyNoInteractions(service);
    }

    @Test
    void duplicateQueryParameterReturnsTheSameFixedError() throws Exception {
        RegistryIngestionService service = mock(RegistryIngestionService.class);
        MockMvc mvc = mvc(service, "expected-token");

        mvc.perform(put("/admin/registries/customers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer expected-token")
                        .queryParam("columns", "email", "email")
                        .contentType("text/csv")
                        .content("email\nfake101@example-corp.test\n"))
                .andExpect(status().isBadRequest())
                .andExpect(content().json("""
                        {"error":"invalid-registry-ingest-request"}
                        """));

        verifyNoInteractions(service);
    }

    @Test
    void authenticationPrecedesQueryParsingAndBodyConsumption() throws Exception {
        RegistryIngestionService service = mock(RegistryIngestionService.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        RegistryAdminController controller = controller(service, "expected-token");

        assertThat(controller.put("customers", "Bearer wrong-token", request).getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);

        verifyNoInteractions(request, service);
    }

    @Test
    void ingestionValidationDetailsAreTranslatedToTheFixed400() throws Exception {
        RegistryIngestionService service = mock(RegistryIngestionService.class);
        when(service.ingest(any(RegistryIngestCommand.class), any(InputStream.class)))
                .thenThrow(new RegistryIngestionException(
                        RegistryIngestionException.Kind.BAD_REQUEST,
                        "unknown-csv-column"));
        MockMvc mvc = mvc(service, "expected-token");

        mvc.perform(put("/admin/registries/customers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer expected-token")
                        .queryParam("columns", "email")
                        .queryParam("replacementKinds", "email:EMAIL")
                        .queryParam("recipe", "synthetic-email:1")
                        .queryParam("blockThreshold", "1")
                        .contentType("text/csv")
                        .content("name\nfake101@example-corp.test\n"))
                .andExpect(status().isBadRequest())
                .andExpect(content().json("""
                        {"error":"invalid-registry-ingest-request"}
                        """))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("unknown-csv-column"))));
    }

    private static MockMvc mvc(RegistryIngestionService service, String token) {
        return MockMvcBuilders.standaloneSetup(controller(service, token)).build();
    }

    private static RegistryAdminController controller(RegistryIngestionService service,
                                                       String token) {
        HamzaProperties props = new HamzaProperties(null, null,
                new HamzaProperties.Edm("/tmp/registries", 10, true, token));
        return new RegistryAdminController(service, props);
    }
}
