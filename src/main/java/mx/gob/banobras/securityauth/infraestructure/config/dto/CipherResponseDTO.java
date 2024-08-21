package mx.gob.banobras.securityauth.infraestructure.config.dto;



/**
 * CipherResponseDTO.java:
 * 
 * Objeto que contiene los datos de respuesta de encritpado y descriptado. 
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see Documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CipherResponseDTO {
	private Integer statusCode;
	private DataDTO dataDTO;
	private ErrorMessageDTO errorMessageDTO;
}


