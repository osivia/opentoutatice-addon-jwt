package org.osivia.jwt.service;

import java.io.UnsupportedEncodingException;

import org.nuxeo.common.xmap.annotation.XNode;
import org.nuxeo.common.xmap.annotation.XObject;
import org.nuxeo.ecm.core.api.ClientException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;

@XObject(value = "token")
public class TokenDescriptor {

    @XNode("@id")
    private String id;

    @XNode("@name")
    private String name;

    @XNode("@key")
    private String key;

    @XNode("@duration")
    private String duration;

    private JWTVerifier verifier;
    private Algorithm algorithm;


    public TokenDescriptor() {
        super();
    }

    public TokenDescriptor(TokenDescriptor algorithmDescriptor) {
        id = algorithmDescriptor.id;
        name = algorithmDescriptor.name;
        key = algorithmDescriptor.key;
        duration = algorithmDescriptor.duration;
    }

    public String getId() {
        return id;
    }

    public Algorithm getAlgorithm() {
        if (algorithm == null) {
            try {
                switch (name) {
                    case "HS256":
                        algorithm = Algorithm.HMAC256(key);
                        break;
                    case "HS384":
                        algorithm = Algorithm.HMAC384(key);
                        break;
                    case "HS512":
                        algorithm = Algorithm.HMAC512(key);
                        break;
                    default:
                        throw new ClientException("aucun algorithme correspondant à " + name);
                }
            } catch (IllegalArgumentException | UnsupportedEncodingException e) {
                throw new ClientException(e);
            }
        }

        return algorithm;
    }

    public JWTVerifier getJWTVerifier() {
        if (verifier == null) {
            verifier = JWT.require(getAlgorithm()).build();
        }

        return verifier;
    }


    public String getDuration() {
        return duration;
    }


    /**
     * @return the name
     */
    public String getName() {
        return name;
    }


    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }


    /**
     * @return the key
     */
    public String getKey() {
        return key;
    }


    /**
     * @param key the key to set
     */
    public void setKey(String key) {
        this.key = key;
    }


    /**
     * @param id the id to set
     */
    public void setId(String id) {
        this.id = id;
    }


    /**
     * @param duration the duration to set
     */
    public void setDuration(String duration) {
        this.duration = duration;
    }

}
