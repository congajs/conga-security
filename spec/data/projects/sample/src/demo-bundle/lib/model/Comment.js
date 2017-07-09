/**
 * @Bass:Document(collection="comments")
 * @Rest:Resource(type="comment")
 */
module.exports = class Comment {

    constructor() {

        /**
         * @Bass:Id
         * @Bass:Field(type="ObjectID", name="_id")
         * @Rest:ID
         */
        this.id = null;

        /**
         * @Bass:Field(type="String", name="body")
         * @Assert:NotBlank
         * @Rest:Attribute
         */
        this.body = null;

        /**
         * @Bass:OneToOne(document="User", name="user_id")
         * @Rest:Relationship(type="one", relatedType="users")
         */
        this.user = null;

        /**
         * @Bass:Version
         * @Bass:Field(type="Number", name="version")
         * @Rest:Attribute
         */
        this.version = 0;

        /**
         * @Bass:CreatedAt
         * @Bass:Field(type="Date", name="created_at")
         * @Rest:Attribute
         */
        this.createdAt = null;

        /**
         * @Bass:UpdatedAt
         * @Bass:Field(type="Date", name="updated_at")
         * @Rest:Attribute
         */
        this.updatedAt = null;

    }
}
