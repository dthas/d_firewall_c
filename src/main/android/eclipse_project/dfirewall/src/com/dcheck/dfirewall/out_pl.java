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

public class out_pl extends Activity
{
	private EditText etip_out;
	private EditText etport_out;
	private String str;
	
	protected void onCreate(Bundle savedInstanceState) 
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.out_pl);
		
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
	    
	    //这是第一种 直接付给此button新的xy坐标
	    //btn3.setX(10);
	    //btn3.setY(30);
	    
	    etip_out 	= (EditText) findViewById(R.id.et_ip_out);
	    etport_out 	= (EditText) findViewById(R.id.et_port_out);
	
	    btn1.setOnClickListener(new Button.OnClickListener()
	    {
	    	public void onClick(View v)
	    	{  
	    		try
	    		{   
	    			//缺省保存目录：/data/data/com.dcheck.dfirewall/files
	    			//FileOutputStream fout =openFileOutput("/data/dfirewall/txt_out_stop_port.txt", MODE_APPEND);   
	    			FileOutputStream fout =openFileOutput("txt_out_stop_port.txt", MODE_APPEND);  
	    		    fout.write(etip_out.getText().toString().getBytes());
	    		    str	= " :";
	    		    fout.write(str.getBytes());
	    		    fout.write(etport_out.getText().toString().getBytes());
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
	    		try
	    		{   
	    			//缺省保存目录：/data/data/com.dcheck.dfirewall/files
	    			//FileOutputStream fout =openFileOutput("/data/dfirewall/txt_out_start_port.txt", MODE_APPEND);   
	    			FileOutputStream fout =openFileOutput("txt_out_start_port.txt", MODE_APPEND);  
	    		    fout.write(etip_out.getText().toString().getBytes());
	    		    str	= " :";
	    		    fout.write(str.getBytes());
	    		    fout.write(etport_out.getText().toString().getBytes());
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
