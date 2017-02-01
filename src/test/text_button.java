package txt_button;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.*;
import java.io.RandomAccessFile;

public class text_button 
{
	public static void main(String[] args)
	{
		text_button_in_pl p2 = new text_button_in_pl();
	}
}

class text_button_in_pl extends JFrame implements ActionListener
{
	private JButton butt_stop_port 	= new JButton("stop");

	public JTextField txt_port	= new JTextField(20);

	private	JFrame frame 		= new JFrame();

	private JPanel p1 		= new JPanel();

	//public	String str_txt;

	public text_button_in_pl()
	{
		//为按钮添加监听器
		//butt_stop_port.addActionListener(new txt_port_ListenerClass());
		butt_stop_port.addActionListener(this);
	
		frame.setLayout(new FlowLayout());

		p1.add(butt_stop_port);
		
		p1.setVisible(true);
		
		p1.setLayout(new FlowLayout());

		frame.add(txt_port);
		frame.add(p1);

		frame.setTitle("shut down the ports");
		frame.setSize(300,300);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setLocationRelativeTo(null);
		frame.setVisible(true);

		//str_txt		= txt_port.getText();
	}

	public void actionPerformed(ActionEvent e)
	{
		//System.out.println(txt_port.getText());

		try
		{
			//FileWriter fw	= new FileWriter("hello.txt");
     			//fw.write(txt_port.getText());  
         		//fw.close();

			RandomAccessFile randomFile = new RandomAccessFile("hello.txt", "rw");
			long fileLength = randomFile.length();
			randomFile.seek(fileLength);
			randomFile.writeBytes(txt_port.getText());
			randomFile.close();
		}
		catch(Exception ee)
		{}
	}	
}

/*
class txt_port_ListenerClass implements ActionListener
{
	@Override
	public void actionPerformed(ActionEvent e) 
	{
		// TODO 自动生成的方法存根
		//??这里怎么显示在文本框中打印出来

		//textField.setText(((JButton)e.getSource()).getText());
		System.out.println(txt_button.p2.txt_port.getText());
	}
}
*/

