package mx.gob.banobras.securityauth.infraestructure.config.dto;


/**
 * TokenizerResponseDTO.java:
 * 
 * Objeto que contiene los datos de respuesta de generacion del Token. 
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
public class TokenizerResponseDTO {
	private Integer statusCode;
	private TokenDTO tokenDTO;
	private ErrorMessageDTO errorMessageDTO;
}


