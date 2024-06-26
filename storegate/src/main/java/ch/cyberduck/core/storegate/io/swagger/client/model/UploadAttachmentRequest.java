/*
 * Storegate api v4.2
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: v4.2
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */


package ch.cyberduck.core.storegate.io.swagger.client.model;

import java.util.Objects;
import java.util.Arrays;
import ch.cyberduck.core.storegate.io.swagger.client.model.AttachmentContent;
import ch.cyberduck.core.storegate.io.swagger.client.model.AttachmentDetailsCompose;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * 
 */
@ApiModel(description = "")
@javax.annotation.Generated(value = "io.swagger.codegen.languages.JavaClientCodegen", date = "2023-08-24T11:36:23.792+02:00")
public class UploadAttachmentRequest {
  @JsonProperty("attachmentDetailsCompose")
  private AttachmentDetailsCompose attachmentDetailsCompose = null;

  @JsonProperty("attachmentContent")
  private AttachmentContent attachmentContent = null;

  @JsonProperty("parentId")
  private String parentId = null;

  public UploadAttachmentRequest attachmentDetailsCompose(AttachmentDetailsCompose attachmentDetailsCompose) {
    this.attachmentDetailsCompose = attachmentDetailsCompose;
    return this;
  }

   /**
   * 
   * @return attachmentDetailsCompose
  **/
  @ApiModelProperty(value = "")
  public AttachmentDetailsCompose getAttachmentDetailsCompose() {
    return attachmentDetailsCompose;
  }

  public void setAttachmentDetailsCompose(AttachmentDetailsCompose attachmentDetailsCompose) {
    this.attachmentDetailsCompose = attachmentDetailsCompose;
  }

  public UploadAttachmentRequest attachmentContent(AttachmentContent attachmentContent) {
    this.attachmentContent = attachmentContent;
    return this;
  }

   /**
   * 
   * @return attachmentContent
  **/
  @ApiModelProperty(value = "")
  public AttachmentContent getAttachmentContent() {
    return attachmentContent;
  }

  public void setAttachmentContent(AttachmentContent attachmentContent) {
    this.attachmentContent = attachmentContent;
  }

  public UploadAttachmentRequest parentId(String parentId) {
    this.parentId = parentId;
    return this;
  }

   /**
   * 
   * @return parentId
  **/
  @ApiModelProperty(value = "")
  public String getParentId() {
    return parentId;
  }

  public void setParentId(String parentId) {
    this.parentId = parentId;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UploadAttachmentRequest uploadAttachmentRequest = (UploadAttachmentRequest) o;
    return Objects.equals(this.attachmentDetailsCompose, uploadAttachmentRequest.attachmentDetailsCompose) &&
        Objects.equals(this.attachmentContent, uploadAttachmentRequest.attachmentContent) &&
        Objects.equals(this.parentId, uploadAttachmentRequest.parentId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(attachmentDetailsCompose, attachmentContent, parentId);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UploadAttachmentRequest {\n");
    
    sb.append("    attachmentDetailsCompose: ").append(toIndentedString(attachmentDetailsCompose)).append("\n");
    sb.append("    attachmentContent: ").append(toIndentedString(attachmentContent)).append("\n");
    sb.append("    parentId: ").append(toIndentedString(parentId)).append("\n");
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

