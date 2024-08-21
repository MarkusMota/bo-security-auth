package mx.gob.banobras.securityauth.infraestructure.config.dto;


/**
 * LdapResponseDTO.java:
 * 
 * Objeto que contiene los datos de respuesta de la autenticacion. 
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
public class LdapResponseDTO {
	private Integer statusCode;
	private LdapDTO ldapDTO;
	private ErrorMessageDTO errorMessageDTO;
}


