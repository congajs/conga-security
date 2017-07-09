/**
 * @Bass:Document(collection="users")
 * @Rest:Resource(type="user")
 */
module.exports = class User {

    constructor() {

        /**
         * @Bass:Id
         * @Bass:Field(type="ObjectID", name="_id")
         * @Rest:ID
         */
        this.id = null;

        /**
         * @Bass:Field(type="String", name="email")
         * @Rest:Attribute
         */
        this.email = null;

        /**
         * @Bass:Field(type="String", name="name")
         * @Rest:Attribute
         */
        this.name = null;

        /**
         * @Bass:Version
         * @Bass:Field(type="Number", name="version")
         * @Rest:Attribute(update=false)
         */
        this.version = 0;

        /**
         * @Bass:CreatedAt
         * @Bass:Field(type="Date", name="created_at")
         * @Rest:Attribute(update=false)
         */
        this.createdAt = null;

        /**
         * @Bass:UpdatedAt
         * @Bass:Field(type="Date", name="updated_at")
         * @Rest:Attribute(update=false)
         */
        this.updatedAt = null;
    }

}
