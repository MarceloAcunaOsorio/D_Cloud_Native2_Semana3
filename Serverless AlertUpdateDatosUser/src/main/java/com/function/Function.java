package com.function;

import java.util.Optional;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;

/**
 * Función Azure para manejar notificaciones de alertas cuando se actualizan datos de usuarios
 */
public class Function {
    // Instancia de Gson para procesar JSON
    private final Gson gson = new Gson();

    /**
     * Función que se activa mediante una petición HTTP POST
     * Procesa las alertas enviadas desde el backend cuando se actualizan datos de usuarios
     */
    @FunctionName("AlertNotification")
    public HttpResponseMessage run(
            @HttpTrigger(
                name = "req",
                methods = {HttpMethod.POST},
                authLevel = AuthorizationLevel.ANONYMOUS)
                HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {
        
        context.getLogger().info("Procesando solicitud de notificación de alerta.");

        try {
            // Obtener el cuerpo de la petición
            String requestBody = request.getBody().orElse("");
            if (requestBody.isEmpty()) {
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body("Por favor proporcione un cuerpo de petición con información de alerta")
                    .build();
            }

            // Convertir el JSON recibido a un objeto
            JsonObject alertData = gson.fromJson(requestBody, JsonObject.class);
            
            // Extraer la información de la alerta
            String message = alertData.get("message").getAsString();
            String userEmail = alertData.get("userEmail").getAsString();
            String modificationType = alertData.get("modificationType").getAsString();
            String userRole = alertData.get("userRole").getAsString();

            // Registrar la información de la alerta
            context.getLogger().info(String.format(
                "Alerta recibida - Tipo: %s, Usuario: %s (%s), Mensaje: %s",
                modificationType, userEmail, userRole, message
            ));

            // Aquí se pueden agregar acciones adicionales como:
            // - Enviar correos electrónicos
            // - Almacenar en una base de datos
            // - Activar otros servicios
            // - etc.

            return request.createResponseBuilder(HttpStatus.OK)
                .body("Notificación de alerta procesada exitosamente")
                .build();

        } catch (Exception e) {
            context.getLogger().severe("Error al procesar la notificación de alerta: " + e.getMessage());
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Error al procesar la notificación de alerta: " + e.getMessage())
                .build();
        }
    }
}
