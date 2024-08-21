package mx.gob.banobras.securityauth.infraestructure.adapter.out.client;

/**
 * LdapVO.java:
 * 
 * Objeto que contiene los datos del usuario en LDAP. 
 *  
 * @author Marcos Gonzalez
 * @version 1.0, 13/06/2024
 * @see Documento "MAR - Marco Arquitectonico de Referencia"
 * @since JDK 17
 */

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class LdapVO {
	private String usuario;
	private String password;
	private String expediente;
	private String cuentaControl;
	private String nombre;
	private String puesto;
	private String area;
	private String extension;
	private Integer activo;
	private String emailPrincipal;
	private String email;
	private List<String> grupoAplicativoPerfil;
	private List<String> listaTotalGrupos;
	private String detalle;
	
	
}
