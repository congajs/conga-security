/**
 * @Bass:Document(collection="articles")
 * @Rest:Resource(type="article")
 */
module.exports = class Article {

    constructor() {

        /**
         * @Bass:Id
         * @Bass:Field(type="ObjectID", name="_id")
         * @Rest:ID
         */
        this.id = null;

        /**
         * @Bass:Field(type="String", name="title")
         * @Rest:Attribute
         */
        this.title = null;

        /**
         * @Bass:Field(type="String", name="body")
         * @Rest:Attribute
         */
        this.body = null;

        /**
         * @Bass:OneToMany(document="Comment")
         * @Rest:Relationship(type="many", relatedType="comments")
         */
        this.comments = [];

        /**
         * @Bass:OneToOne(document="User", name="user_id")
         * @Rest:Relationship(type="one", relatedType="user")
         */
        this.author = null;

        /**
         * @Bass:Field(type="String", name="not_exposed")
         * @Rest:Attribute(expose=false)
         */
        this.notExposed = null;

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
