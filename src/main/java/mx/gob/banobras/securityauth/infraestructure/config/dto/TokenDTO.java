package mx.gob.banobras.securityauth.infraestructure.config.dto;

/**
 * TokenDTO.java:
 * 
 * Objeto que contiene los datos del Token.. 
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see Documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenDTO {
	public boolean valid;
	public String token;
	public String refreshToken;
	
	
}
