package com.dcheck.dfirewall;

import android.app.Activity;
//import android.content.DialogInterface.OnClickListener;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;

import java.io.FileOutputStream;  
import java.io.IOException;
import java.io.FileNotFoundException;

public class in_pl extends Activity
{
	private EditText etip_in;
	private EditText etport_in;
	private String str;
	
	/*
	//写数据  
	public void writef(String fileName,String writestr) throws IOException
	{   
		try
		{   
			FileOutputStream fout =openFileOutput(fileName, MODE_PRIVATE);   
		    byte [] bytes = writestr.getBytes();   
		    fout.write(bytes);   
		    fout.close();   
		}
		catch (FileNotFoundException e) 
		{  
            e.printStackTrace();  
        }
		catch(IOException e)
		{   
		    e.printStackTrace();   
		}   
	}  
	*/ 
		
	protected void onCreate(Bundle savedInstanceState) 
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.in_pl);
		
		Button btn1;  
		Button btn2;
		Button btn3;
		
		btn1 = (Button)findViewById(R.id.button_1);  
	    btn2 = (Button)findViewById(R.id.button_2);  
	    btn3 = (Button)findViewById(R.id.button_3);
	    
	    btn2.setHeight(50);
	    btn2.setWidth(100);
	    
	    btn1.setHeight(50);
	    btn1.setWidth(100);
	    
	    btn3.setHeight(50);
	    btn3.setWidth(100);
	    
	    etip_in 	= (EditText) findViewById(R.id.et_ip_in);
	    etport_in 	= (EditText) findViewById(R.id.et_port_in);
	    
	    btn1.setOnClickListener(new Button.OnClickListener()
	    {
	    	public void onClick(View v)
	    	{  
	    		//EditText et =(EditText)findViewById(R.id.edit_text_1); 
		    	//String str=et.getText().toString();
		    	//writef("/data/dfirewall/txt_in_start_port.txt" ,str);
		    	
	    		
	    		try
	    		{   
	    			//缺省保存目录：/data/data/com.dcheck.dfirewall/files
	    			//FileOutputStream fout =openFileOutput("/data/dfirewall/txt_in_stop_port.txt", MODE_APPEND);   
	    			FileOutputStream fout =openFileOutput("txt_in_stop_port.txt", MODE_APPEND);  
	    			fout.write(etip_in.getText().toString().getBytes());
		    		str	= " :";
		    		fout.write(str.getBytes());
		    		fout.write(etport_in.getText().toString().getBytes());
		    		str	= "\n";
		    		fout.write(str.getBytes());
		    		fout.flush();
		    		fout.close(); 
	    		}
	    		catch (FileNotFoundException e) 
	    		{  
	                e.printStackTrace();  
	            }
	    		catch(IOException e)
	    		{   
	    		    e.printStackTrace();   
	    		} 
	        }              
	    });  
	    
	    btn2.setOnClickListener(new Button.OnClickListener()
	    {
	    	public void onClick(View v)
	    	{  
	    		//EditText et =(EditText)findViewById(R.id.edit_text_1); 
		    	//String str=et.getText().toString();
		    	//writeFile("/data/dfirewall/txt_in_stop_port.txt" ,str);
		    	
		    	try
	    		{   
		    		//缺省保存目录：/data/data/com.dcheck.dfirewall/files
	    			//FileOutputStream fout =openFileOutput("/data/dfirewall/txt_in_start_port.txt", MODE_APPEND);
	    			FileOutputStream fout =openFileOutput("txt_in_start_port.txt", MODE_APPEND);
	    			fout.write(etip_in.getText().toString().getBytes());
		    		str	= " :";
		    		fout.write(str.getBytes());
		    		fout.write(etport_in.getText().toString().getBytes());
		    		str	= "\n";
		    		fout.write(str.getBytes());
		    		fout.flush();
		    		fout.close();   
	    		}
	    		catch (FileNotFoundException e) 
	    		{  
	                e.printStackTrace();  
	            }
	    		catch(IOException e)
	    		{   
	    		    e.printStackTrace();   
	    		} 
	        }	    	             
	    }); 
	    
	    btn3.setOnClickListener(new Button.OnClickListener()
	    {
	    	public void onClick(View v)
	    	{  
	    		finish();
	        }              
	    }); 
	}
	
	
}