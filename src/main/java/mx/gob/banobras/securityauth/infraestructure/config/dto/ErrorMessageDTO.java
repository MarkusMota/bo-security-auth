package mx.gob.banobras.securityauth.infraestructure.config.dto;
/**
 * ErrorMessageDTO.java:
 * 
 * Objeto que contiene los datos para el mensaje de error. 
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see Documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */
import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ErrorMessageDTO {
	  private int statusCode;
	  private Date timestamp;
	  private String message;
}
