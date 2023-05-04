import mongoose from 'mongoose';
import config from 'config';

const dbUrl = `mongodb+srv://${config.get('dbName')}:${config.get(
  'dbPass'
)}@auth-tutorial.1qtx3fx.mongodb.net/?retryWrites=true&w=majority`;

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
