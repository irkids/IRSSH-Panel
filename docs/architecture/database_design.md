# Database Design Document

## Schema Design
### Users Collection
```javascript
{
  _id: ObjectId,
  username: String,
  email: String,
  password: String,
  role: String,
  status: String,
  createdAt: Date,
  updatedAt: Date
}
