package com.dcheck.dfirewall;

import android.app.Activity;
//import android.content.DialogInterface.OnClickListener;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;

import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button; 

import android.content.Intent;

public class MainActivity extends Activity
//public class MainActivity extends Activity implements OnClickListener 
{
	//private Button button;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		//setContentView(R.layout.in_pl);
		//button = (Button) findViewById(R.id.button);
		//button.setOnClickListener(this);
		
		Button btn1;  
		Button btn2;  
		Button btn3;
		Button btn4;
		Button btn5;
        
        btn1 = (Button)findViewById(R.id.button_1);  
        btn2 = (Button)findViewById(R.id.button_2);  
        btn3 = (Button)findViewById(R.id.button_3); 
        btn4 = (Button)findViewById(R.id.button_4);
        btn5 = (Button)findViewById(R.id.button_5);
        
        //btn1.setOnClickListener(this);
        //btn2.setOnClickListener(this);
        //btn3.setOnClickListener(this);
        //btn4.setOnClickListener(this);
        //btn5.setOnClickListener(this);
        
        btn1.setOnClickListener(new Button.OnClickListener()
        {
        	public void onClick(View v)
        	{  
                
            }              
        });  
        
        btn2.setOnClickListener(new Button.OnClickListener()
        {
        	public void onClick(View v)
        	{  
                
            }              
        }); 
        
        btn3.setOnClickListener(new Button.OnClickListener()
        {
        	@Override 
        	public void onClick(View v)
        	{  
        		 Intent i = new Intent(MainActivity.this , in_pl.class);
        		 startActivity(i);
            }              
        }); 
        
        btn4.setOnClickListener(new Button.OnClickListener()
        {
        	public void onClick(View v)
        	{  
        		Intent i = new Intent(MainActivity.this , out_pl.class);
       		 	startActivity(i);
            }              
        });
        
        btn5.setOnClickListener(new Button.OnClickListener()
        {
        	public void onClick(View v)
        	{  
                finish();
            }              
        });  
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
}
