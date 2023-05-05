import mongoose from 'mongoose';
import config from 'config';

const username = encodeURIComponent(config.get('dbName'));
const password = encodeURIComponent(config.get('dbPass'));
const database = 'shop-application';

const dbUrl = `mongodb+srv://${username}:${password}@shop.dmzopq4.mongodb.net/${database}?retryWrites=true&w=majority`;

const connectDB = async () => {
  try {
    await mongoose.connect(dbUrl);
    console.log('Database connected...');
  } catch (error: any) {
    console.log(error.message);
    setTimeout(connectDB, 5000);
  }
};

export default connectDB;
