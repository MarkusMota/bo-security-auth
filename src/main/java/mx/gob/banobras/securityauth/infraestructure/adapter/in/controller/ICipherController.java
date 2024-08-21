package mx.gob.banobras.securityauth.infraestructure.adapter.in.controller;

/**
 * ICipherCotroller.java:
 * 
 * Interface para exponer los servicios para cifrar datos
 * 
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see Documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import mx.gob.banobras.securityauth.infraestructure.config.dto.CipherResponseDTO;

@Tag(name = "Encriptar datos.", description = "Servicio que prove&eacute; el encriptado de datos.")
@RequestMapping("/security-auth/v1/encrypt")
public interface ICipherController {

	/**
	 * Metodo para obtener encriptar una cadena.
	 * 
	 * @param data datos a desecriptar.
	 * 
	 * @return CipherResponseDTO objeto que contien los dato encriptados.
	 * @throws Exception Excepción durante el proceso.
	 * 
	 */
	@Operation(summary = "Servicio para encriptar datos.", description = "Servicio para encriptar datos.")
	@Parameter(name = "data", required = true, description = "Datos a encriptar.", example = "MGarcia 23182kk")
	@ApiResponse(responseCode = "400", description = "Solicitud err&oacute;nea.")
	@ApiResponse(responseCode = "404", description = "Recurso no encontrado.")
	@ApiResponse(responseCode = "500", description = "Error interno.")
	@PostMapping("/encode")
	public ResponseEntity<CipherResponseDTO> encode(@RequestHeader(value = "data") String data);

	/**
	 * Metodo para obtener desencriptar una cadena.
	 * 
	 * @param data datos a desecriptar.
	 * 
	 * @return regresa la cadena desencriptada.
	 * @throws Exception Excepción durante el proceso.
	 * 
	 */
	@Operation(summary = "Servicio para desencriptar datos.", description = "Servicio para desencriptar datos.")
	@Parameter(name = "data", required = true, description = "Datos a desencriptar.", example = "8046E3831C1548F141EE468699B6F62B")
	@ApiResponse(responseCode = "400", description = "Solicitud err&oacute;nea.")
	@ApiResponse(responseCode = "404", description = "Recurso no encontrado.")
	@ApiResponse(responseCode = "500", description = "Error interno.")
	@PostMapping("/decode")
	public ResponseEntity<CipherResponseDTO> decode(@RequestHeader(value = "data") String data);

}
