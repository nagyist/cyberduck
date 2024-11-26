/*
 * DeepAdmin API
 * General API for DeepCloud Admin / Subscription Service
 *
 * OpenAPI spec version: 1.0.0
 * Contact: support@deepcloud.swiss
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */

package ch.cyberduck.core.deepcloud.io.swagger.client.model;

import java.util.Objects;
import java.util.Arrays;
import ch.cyberduck.core.deepcloud.io.swagger.client.model.Address;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.ArrayList;
import java.util.List;
/**
 * Simple Unit Serializer with no tree/children/parent crawling capabilities To be extended for use in more specialized actions
 */
@Schema(description = "Simple Unit Serializer with no tree/children/parent crawling capabilities To be extended for use in more specialized actions")


public class UnitRoles {
  @JsonProperty("group_id")
  private String groupId = null;

  @JsonProperty("name")
  private String name = null;

  @JsonProperty("display_name")
  private String displayName = null;

  @JsonProperty("default_address")
  private Address defaultAddress = null;

  @JsonProperty("metadata")
  private Object metadata = null;

  @JsonProperty("logo")
  private String logo = null;

  @JsonProperty("roles")
  private List<String> roles = new ArrayList<>();

   /**
   * Get groupId
   * @return groupId
  **/
  @Schema(required = true, description = "")
  public String getGroupId() {
    return groupId;
  }

  public UnitRoles name(String name) {
    this.name = name;
    return this;
  }

   /**
   * A unique email address (which could not exist) to reference this entity
   * @return name
  **/
  @Schema(description = "A unique email address (which could not exist) to reference this entity")
  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public UnitRoles displayName(String displayName) {
    this.displayName = displayName;
    return this;
  }

   /**
   * Get displayName
   * @return displayName
  **/
  @Schema(required = true, description = "")
  public String getDisplayName() {
    return displayName;
  }

  public void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  public UnitRoles defaultAddress(Address defaultAddress) {
    this.defaultAddress = defaultAddress;
    return this;
  }

   /**
   * Get defaultAddress
   * @return defaultAddress
  **/
  @Schema(required = true, description = "")
  public Address getDefaultAddress() {
    return defaultAddress;
  }

  public void setDefaultAddress(Address defaultAddress) {
    this.defaultAddress = defaultAddress;
  }

   /**
   * Get metadata
   * @return metadata
  **/
  @Schema(required = true, description = "")
  public Object getMetadata() {
    return metadata;
  }

  public UnitRoles logo(String logo) {
    this.logo = logo;
    return this;
  }

   /**
   * For reading, it returns the URL. For writing you need to provide the image base64 encoded, like \&quot;data:image/png;base64,&lt;BASE64_DATA&gt;\&quot;.
   * @return logo
  **/
  @Schema(description = "For reading, it returns the URL. For writing you need to provide the image base64 encoded, like \"data:image/png;base64,<BASE64_DATA>\".")
  public String getLogo() {
    return logo;
  }

  public void setLogo(String logo) {
    this.logo = logo;
  }

   /**
   * Get roles
   * @return roles
  **/
  @Schema(required = true, description = "")
  public List<String> getRoles() {
    return roles;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UnitRoles unitRoles = (UnitRoles) o;
    return Objects.equals(this.groupId, unitRoles.groupId) &&
        Objects.equals(this.name, unitRoles.name) &&
        Objects.equals(this.displayName, unitRoles.displayName) &&
        Objects.equals(this.defaultAddress, unitRoles.defaultAddress) &&
        Objects.equals(this.metadata, unitRoles.metadata) &&
        Objects.equals(this.logo, unitRoles.logo) &&
        Objects.equals(this.roles, unitRoles.roles);
  }

  @Override
  public int hashCode() {
    return Objects.hash(groupId, name, displayName, defaultAddress, metadata, logo, roles);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UnitRoles {\n");
    
    sb.append("    groupId: ").append(toIndentedString(groupId)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    displayName: ").append(toIndentedString(displayName)).append("\n");
    sb.append("    defaultAddress: ").append(toIndentedString(defaultAddress)).append("\n");
    sb.append("    metadata: ").append(toIndentedString(metadata)).append("\n");
    sb.append("    logo: ").append(toIndentedString(logo)).append("\n");
    sb.append("    roles: ").append(toIndentedString(roles)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}